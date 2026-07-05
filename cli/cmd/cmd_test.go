package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amplify-lab/damping/cli/paths"
	"github.com/amplify-lab/damping/cli/ui"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

// setupTestEnv points every damping path at fresh temp directories so tests
// never touch a real ~/.damping or a real agent settings file.
func setupTestEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DAMPING_HOME", filepath.Join(dir, "damping-home"))
	t.Setenv("DAMPING_CLAUDE_SETTINGS", filepath.Join(dir, "claude", "settings.json"))
	t.Setenv("DAMPING_CURSOR_HOOKS", filepath.Join(dir, "cursor", "hooks.json"))
	// `init` only registers a hook for an agent whose config directory it can
	// detect — pre-create both so tests exercise the "agent installed" path.
	if err := os.MkdirAll(filepath.Join(dir, "claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := NewRootCmd()
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

// syncBuffer is a concurrency-safe io.Writer wrapper around bytes.Buffer —
// unlike bytes.Buffer itself, its String() is safe to poll from a test's
// main goroutine while a command started via startLogFollow is still
// writing to it in a background goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startLogFollow starts `damping log --follow ...` in the background,
// returning concurrency-safe stdout/stderr buffers the caller can poll
// (via waitForContains) while the command is still running, and a channel
// that receives its final error once ctx is cancelled and it stops.
func startLogFollow(t *testing.T, ctx context.Context, args ...string) (stdout, stderr *syncBuffer, done <-chan error) {
	t.Helper()
	root := NewRootCmd()
	stdout, stderr = &syncBuffer{}, &syncBuffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetIn(strings.NewReader(""))
	root.SetArgs(args)
	doneCh := make(chan error, 1)
	go func() { doneCh <- root.ExecuteContext(ctx) }()
	return stdout, stderr, doneCh
}

// waitForContains polls buf until its content contains substr or timeout
// elapses — used instead of a fixed sleep so follow-mode tests aren't
// tuned to a specific poll interval/sleep-duration ratio that could be
// flaky on a slower or more loaded machine.
func waitForContains(t *testing.T, buf *syncBuffer, substr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), substr) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %q, got:\n%s", timeout, substr, buf.String())
}

func TestInit_WritesPolicyAndRegistersClaudeHook(t *testing.T) {
	setupTestEnv(t)

	out, _, err := run(t, "", "init")
	if err != nil {
		t.Fatalf("init: %v (stdout: %s)", err, out)
	}
	if !strings.Contains(out, "Setup complete") {
		t.Fatalf("expected setup-complete message, got: %s", out)
	}

	statusOut, _, err := run(t, "", "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(statusOut, "Damping: ON") {
		t.Fatalf("expected Damping: ON after init, got: %s", statusOut)
	}
	if !strings.Contains(statusOut, "rules)") {
		t.Fatalf("expected the policy rule count in status output, got: %s", statusOut)
	}
	if !strings.Contains(statusOut, "claude-code (active)") || !strings.Contains(statusOut, "cursor (active)") {
		t.Fatalf("expected both agents listed as active after init detected them, got: %s", statusOut)
	}
	if !strings.Contains(statusOut, "Sync:    disabled") {
		t.Fatalf("expected sync to be reported disabled (team tier is Phase 4, not implemented), got: %s", statusOut)
	}
}

func TestStatus_NoAgentsRegisteredShowsHint(t *testing.T) {
	setupTestEnv(t)
	// Deliberately skip `init` — no hooks have ever been registered, and no
	// policy file exists yet either. `damping doctor` already treats a
	// pre-init, nonexistent policy file as Code:4 ("Policy file invalid");
	// status now matches that same convention for the identical state, so
	// this exercises both behaviors in one pass rather than requiring a
	// separate exit-code assertion.
	statusOut, _, err := run(t, "", "status")
	var exitErr *ExitCodeError
	if !isExitCodeError(err, &exitErr) || exitErr.Code != 4 {
		t.Fatalf("expected ExitCodeError{Code:4} pre-init (no policy file yet), got %v", err)
	}
	if !strings.Contains(statusOut, "damping init") {
		t.Fatalf("expected a hint to run `damping init` when no agent is registered, got: %s", statusOut)
	}
}

// TestStatus_WarnsWhenPolicyFileFailsToLoad is a regression test for a real
// UX gap found via a manual walkthrough of the real binary:
// IsDisabled()'s "ON"/"OFF" line only ever reflected the `damping off`
// marker file, entirely independent of whether the policy file it's
// supposed to enforce could even be read — with an unreadable policy file,
// cli/cmd/hook.go's runHook fails open on every single action (logs
// degraded, exits 0), yet status still said a plain "Damping: ON" with the
// actual problem buried in a secondary Policy: line a skim could miss.
func TestStatus_WarnsWhenPolicyFileFailsToLoad(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	statusOut, _, err := run(t, "", "--config", "/nonexistent/policy.yaml", "status")
	// A follow-up review noted `damping doctor` already treats this same
	// policy.LoadConfig failure as Code:4 — status now matches, so a script
	// chaining `damping status && deploy` gets a real non-zero signal
	// instead of silently continuing on exit 0 next to a loud warning.
	var exitErr *ExitCodeError
	if !isExitCodeError(err, &exitErr) || exitErr.Code != 4 {
		t.Fatalf("expected ExitCodeError{Code:4} when the policy file fails to load, got %v", err)
	}
	if !strings.Contains(statusOut, "Damping: ON, but NOT protecting you") {
		t.Fatalf("expected the headline ON line to warn about the unloadable policy file, got:\n%s", statusOut)
	}
}

func TestDoctor_PassesAfterInit(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	out, _, err := run(t, "", "doctor")
	if err != nil {
		t.Fatalf("expected doctor to pass after init, got error: %v (output: %s)", err, out)
	}
	if !strings.Contains(out, "0 check(s) failed") {
		t.Fatalf("expected 0 failed checks, got: %s", out)
	}
}

func TestDoctor_FailsWhenHookRemovedOutsideOff(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	// First doctor run establishes the "hook is present" baseline.
	if _, _, err := run(t, "", "doctor"); err != nil {
		t.Fatalf("first doctor run: %v", err)
	}

	// Simulate something other than `damping off` wiping the settings file —
	// see features/self_protection.feature.
	claudeSettings := claudeSettingsPath()
	if err := os.WriteFile(claudeSettings, []byte("{}"), 0o644); err != nil {
		t.Fatalf("simulating hook removal: %v", err)
	}

	out, _, err := run(t, "", "doctor")
	var exitErr *ExitCodeError
	if err == nil {
		t.Fatalf("expected doctor to report a failure, got none. Output: %s", out)
	} else if !isExitCodeError(err, &exitErr) || exitErr.Code != 4 {
		t.Fatalf("expected ExitCodeError{Code:4}, got %v", err)
	}
	if !strings.Contains(out, "hook missing") {
		t.Fatalf("expected a hook-missing warning, got: %s", out)
	}
}

// TestDoctor_WarnsWhenPolicyHashChanges exercises the tamper-evidence check
// described in docs/threat-model.md §8: doctor remembers the policy file's
// hash between runs and flags any change, without needing to understand
// what specifically changed.
func TestDoctor_WarnsWhenPolicyHashChanges(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	// First run establishes the hash baseline.
	if _, _, err := run(t, "", "doctor"); err != nil {
		t.Fatalf("first doctor run: %v", err)
	}

	policyPath, err := paths.Policy()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	// Still valid YAML, just different content — enough to change the hash.
	if err := os.WriteFile(policyPath, append(data, []byte("\n# tampered\n")...), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err := run(t, "", "doctor")
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if !strings.Contains(out, "hash changed") {
		t.Fatalf("expected a policy-hash-changed warning, got: %s", out)
	}
	if !strings.Contains(out, "1 warning") {
		t.Fatalf("expected the hash change to count as a warning (not a failure), got: %s", out)
	}
}

func TestPolicyList_ShowsAllRules(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	out, _, err := run(t, "", "policy", "list")
	if err != nil {
		t.Fatalf("policy list: %v", err)
	}
	if !strings.Contains(out, "destructive.rm_rf_protected") {
		t.Fatalf("expected the default rm_rf rule in the listing, got: %s", out)
	}
}

func TestPolicyTest_AllowedCommandExitsZero(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	out, _, err := run(t, "", "policy", "test", "git status")
	if err != nil {
		t.Fatalf("expected exit 0 for a safe command, got error %v", err)
	}
	if !strings.Contains(out, "Would ALLOW") {
		t.Fatalf("expected an ALLOW verdict, got: %s", out)
	}
}

func TestPolicyTest_FlaggedCommandExitsThree(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	out, _, err := run(t, "", "policy", "test", "rm -rf ~/")
	var exitErr *ExitCodeError
	if !isExitCodeError(err, &exitErr) || exitErr.Code != 3 {
		t.Fatalf("expected ExitCodeError{Code:3} for a flagged command, got %v", err)
	}
	if !strings.Contains(out, "Would PROMPT") {
		t.Fatalf("expected a PROMPT verdict, got: %s", out)
	}
}

func TestOnOff_TogglesEnforcementState(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	out, _, err := run(t, "", "off")
	if err != nil {
		t.Fatalf("off: %v", err)
	}
	if !strings.Contains(out, "now OFF") {
		t.Fatalf("expected an OFF confirmation, got: %s", out)
	}

	statusOut, _, err := run(t, "", "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(statusOut, "Damping: OFF") {
		t.Fatalf("expected Damping: OFF, got: %s", statusOut)
	}

	if _, _, err := run(t, "", "on"); err != nil {
		t.Fatalf("on: %v", err)
	}
	statusOut, _, err = run(t, "", "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(statusOut, "Damping: ON") {
		t.Fatalf("expected Damping: ON after re-enabling, got: %s", statusOut)
	}
}

// TestOn_WarnsWhenPolicyFileFailsToLoad is a regression test for a gap a
// review found: `damping on` used to silently re-enable enforcement without
// ever checking whether the policy it just turned back on could actually
// load — the exact moment a user is most likely to trust "back ON" means
// "protected" without separately re-checking `damping status`.
func TestOn_WarnsWhenPolicyFileFailsToLoad(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, _, err := run(t, "", "off"); err != nil {
		t.Fatalf("off: %v", err)
	}

	out, _, err := run(t, "", "--config", "/nonexistent/policy.yaml", "on")
	if err != nil {
		t.Fatalf("on: %v", err)
	}
	if !strings.Contains(out, "back ON") {
		t.Fatalf("expected the usual back-ON confirmation, got: %s", out)
	}
	if !strings.Contains(out, "NOT protecting you") {
		t.Fatalf("expected a warning that the policy file failed to load, got: %s", out)
	}
}

// TestOn_NoWarningWhenPolicyFileLoadsFine guards against the warning added
// for TestOn_WarnsWhenPolicyFileFailsToLoad firing unconditionally — the
// common case (policy loads fine) must stay quiet.
func TestOn_NoWarningWhenPolicyFileLoadsFine(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, _, err := run(t, "", "off"); err != nil {
		t.Fatalf("off: %v", err)
	}

	out, _, err := run(t, "", "on")
	if err != nil {
		t.Fatalf("on: %v", err)
	}
	if strings.Contains(out, "NOT protecting you") {
		t.Fatalf("expected no policy-load warning when the policy is fine, got: %s", out)
	}
}

// TestOff_WritesSelfDisableAuditEvent is required by
// features/self_protection.feature: "damping off" is the single most
// security-sensitive action Damping has, so it must never be exempt from
// the audit trail it enforces on everything else.
func TestOff_WritesSelfDisableAuditEvent(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, _, err := run(t, "", "off"); err != nil {
		t.Fatalf("off: %v", err)
	}

	logOut, _, err := run(t, "", "log", "--outcome", "allow")
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	if strings.Contains(logOut, "No audit events") {
		t.Fatal("expected an audit event for the self_disable action")
	}

	jsonOut, _, err := run(t, "", "log", "--json")
	if err != nil {
		t.Fatalf("log --json: %v", err)
	}
	var e struct {
		ActionType string `json:"action_type"`
		Actor      string `json:"actor"`
	}
	if err := json.Unmarshal([]byte(strings.SplitN(jsonOut, "\n", 2)[0]), &e); err != nil {
		t.Fatalf("parsing --json output: %v", err)
	}
	if e.ActionType != "self_disable" {
		t.Fatalf("expected action_type self_disable, got %q", e.ActionType)
	}
}

func TestOff_ForFlag_RejectsInvalidDuration(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	_, _, err := run(t, "", "off", "--for", "not-a-duration")
	if err == nil {
		t.Fatal("expected an error for an invalid --for duration")
	}
	if !strings.Contains(err.Error(), "--for") {
		t.Fatalf("expected the error to mention --for, got: %v", err)
	}
}

func TestOff_ForFlag_AutoReEnablesAfterExpiry(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, _, err := run(t, "", "off", "--for", "1h"); err != nil {
		t.Fatalf("off --for 1h: %v", err)
	}

	// Still disabled right after — the duration hasn't elapsed.
	stillOff, err := IsDisabled()
	if err != nil {
		t.Fatalf("IsDisabled: %v", err)
	}
	if !stillOff {
		t.Fatal("expected Damping to still be off immediately after 'off --for 1h'")
	}

	// Rewrite the marker as if the duration already expired, without
	// waiting a real hour — this exercises IsDisabled's expiry comparison
	// directly rather than the clock.
	marker, err := paths.DisabledMarker()
	if err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-1 * time.Minute).Format(time.RFC3339)
	if err := os.WriteFile(marker, []byte("off\nuntil="+expired+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	disabled, err := IsDisabled()
	if err != nil {
		t.Fatalf("IsDisabled: %v", err)
	}
	if disabled {
		t.Fatal("expected IsDisabled to report false (auto re-enabled) once the --for duration has expired")
	}

	// And the marker file itself should have been cleaned up.
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("expected the expired marker file to be removed, stat err: %v", err)
	}
}

func TestPolicyValidate_AcceptsTheShippedDefault(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	out, _, err := run(t, "", "policy", "validate")
	if err != nil {
		t.Fatalf("expected the shipped default policy to validate cleanly, got %v", err)
	}
	if !strings.Contains(out, "valid") {
		t.Fatalf("expected a success message, got: %s", out)
	}
}

func TestPolicyValidate_RejectsUnknownRuleID(t *testing.T) {
	setupTestEnv(t)
	dir := t.TempDir()
	badPolicy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(badPolicy, []byte("version: 1\nrules:\n  - id: not_a_real_rule\n    description: x\n    risk: low\n    action: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := run(t, "", "--config", badPolicy, "policy", "validate")
	if err == nil {
		t.Fatal("expected an error for a policy file referencing an unknown rule id")
	}
}

func TestHook_AllowsSafeCommand(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	stdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}`
	_, _, err := run(t, stdin, "hook", "pretooluse")
	if err != nil {
		t.Fatalf("expected exit 0 for a safe command, got %v", err)
	}
}

func TestHook_DeniesKnownSandboxBypass(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	stdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"/proc/self/root/usr/bin/npx rm -rf /"}}`
	_, stderr, err := run(t, stdin, "hook", "pretooluse")
	var exitErr *ExitCodeError
	if !isExitCodeError(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected ExitCodeError{Code:2} for a known sandbox bypass, got %v", err)
	}
	if stderr == "" {
		t.Fatal("expected a reason to be printed to stderr for a hard deny")
	}
}

// TestHook_DeniesAgentAttemptToDisableDamping is the end-to-end version of
// features/self_protection.feature's "agent cannot invoke the disable path"
// scenario — through the real hook, not just the policy engine directly.
func TestHook_DeniesAgentAttemptToDisableDamping(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	stdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"damping off"}}`
	_, stderr, err := run(t, stdin, "hook", "pretooluse")
	var exitErr *ExitCodeError
	if !isExitCodeError(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected the agent's attempt to run 'damping off' to be hard-denied (Code:2), got %v", err)
	}
	if stderr == "" {
		t.Fatal("expected a reason to be printed to stderr for a hard deny")
	}

	// The marker file must not have been created — the disable attempt was
	// blocked before it ever reached a real `damping off` invocation.
	statusOut, _, err := run(t, "", "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(statusOut, "Damping: ON") {
		t.Fatalf("expected Damping to still be ON after the denied disable attempt, got: %s", statusOut)
	}
}

func TestHook_PromptWithoutTTYDefaultsToDenyAndLogsDegraded(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Prompt-tier command; the test process has no controlling terminal, so
	// this exercises the "no TTY available -> deny by default" fallback in
	// runHook rather than a real interactive resolution.
	stdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf ~/"}}`
	_, _, err := run(t, stdin, "hook", "pretooluse")
	var exitErr *ExitCodeError
	if !isExitCodeError(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected the no-TTY fallback to deny (Code:2), got %v", err)
	}
}

func TestHook_IgnoresNonBashTools(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	stdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"command":"rm -rf /"}}`
	_, _, err := run(t, stdin, "hook", "pretooluse")
	if err != nil {
		t.Fatalf("expected non-Bash tool calls to pass through untouched, got %v", err)
	}
}

func TestHook_MalformedInputFailsOpenButLogsDegraded(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	_, _, err := run(t, "not valid json", "hook", "pretooluse")
	if err != nil {
		t.Fatalf("expected malformed input to fail open (exit 0), got %v", err)
	}

	logOut, _, err := run(t, "", "log", "--outcome", "degraded")
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	if strings.Contains(logOut, "No audit events") {
		t.Fatal("expected a degraded audit record for malformed hook input")
	}
}

// TestHook_PersistsAlwaysAllowPattern exercises the full loop end-to-end:
// a Prompt-tier command resolved via "Always allow" ([A]) must be written
// back into the policy file, and a *second* identical command must then be
// silently allowed without the prompter being invoked at all — the
// always_allow pattern short-circuits policy evaluation before it ever
// reaches the rm_rf_protected rule again.
func TestHook_PersistsAlwaysAllowPattern(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	orig := newTTYPrompter
	defer func() { newTTYPrompter = orig }()

	newTTYPrompter = func() (ui.Prompter, func(), error) {
		return ui.TTYPrompter{In: strings.NewReader("A\n"), Out: io.Discard}, func() {}, nil
	}

	stdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf ~/"}}`
	if _, _, err := run(t, stdin, "hook", "pretooluse"); err != nil {
		t.Fatalf("expected the always-allow resolution to permit the command, got %v", err)
	}

	// A second, independent evaluation of the exact same command must now
	// resolve to a plain allow via the persisted pattern — proven by never
	// invoking the prompter again.
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		t.Fatal("prompter must not be invoked once the exact command is in always_allow")
		return ui.TTYPrompter{}, func() {}, nil
	}
	if _, _, err := run(t, stdin, "hook", "pretooluse"); err != nil {
		t.Fatalf("expected the second identical command to be silently allowed via the persisted pattern, got %v", err)
	}
}

func TestHook_PersistsAlwaysDenyPattern(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	orig := newTTYPrompter
	defer func() { newTTYPrompter = orig }()
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		return ui.TTYPrompter{In: strings.NewReader("D\n"), Out: io.Discard}, func() {}, nil
	}

	stdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf ~/scratch"}}`
	var exitErr *ExitCodeError
	if _, _, err := run(t, stdin, "hook", "pretooluse"); !isExitCodeError(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected the always-deny resolution to deny the command (Code:2), got %v", err)
	}

	newTTYPrompter = func() (ui.Prompter, func(), error) {
		t.Fatal("prompter must not be invoked once the exact command is in always_deny")
		return ui.TTYPrompter{}, func() {}, nil
	}
	if _, _, err := run(t, stdin, "hook", "pretooluse"); !isExitCodeError(err, &exitErr) || exitErr.Code != 2 {
		t.Fatalf("expected the second identical command to be silently denied via the persisted pattern, got %v", err)
	}
}

func TestHook_RespectsOff(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, _, err := run(t, "", "off"); err != nil {
		t.Fatalf("off: %v", err)
	}
	stdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`
	_, _, err := run(t, stdin, "hook", "pretooluse")
	if err != nil {
		t.Fatalf("expected hook to no-op while off, got %v", err)
	}
}

func TestLog_CLIAndMCPShareOneAuditTrailAndFilterCorrectly(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	stdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"/proc/self/root/usr/bin/npx rm -rf /"}}`
	if _, _, err := run(t, stdin, "hook", "pretooluse"); !isExitCodeError(err, new(*ExitCodeError)) {
		t.Fatalf("expected the setup command to hard-deny, got %v", err)
	}

	all, _, err := run(t, "", "log")
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	if strings.Contains(all, "No audit events") {
		t.Fatal("expected at least one audit event after a hook interception")
	}

	cliOnly, _, err := run(t, "", "log", "--channel", "cli")
	if err != nil {
		t.Fatalf("log --channel cli: %v", err)
	}
	if strings.Contains(cliOnly, "No audit events") {
		t.Fatal("expected the cli-channel event to show up when filtering by channel=cli")
	}

	mcpOnly, _, err := run(t, "", "log", "--channel", "mcp")
	if err != nil {
		t.Fatalf("log --channel mcp: %v", err)
	}
	if !strings.Contains(mcpOnly, "No audit events") {
		t.Fatal("expected no mcp-channel events yet (only a CLI hook ran)")
	}
}

func TestLog_LimitShowsOnlyMostRecent(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	commands := []string{
		"/proc/self/root/one rm -rf /",
		"/proc/self/root/two rm -rf /",
		"/proc/self/root/three rm -rf /",
	}
	for _, c := range commands {
		stdin := fmt.Sprintf(`{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":%q}}`, c)
		if _, _, err := run(t, stdin, "hook", "pretooluse"); !isExitCodeError(err, new(*ExitCodeError)) {
			t.Fatalf("expected a hard deny for %q, got %v", c, err)
		}
	}

	out, _, err := run(t, "", "log", "--limit", "2")
	if err != nil {
		t.Fatalf("log --limit 2: %v", err)
	}
	if strings.Count(out, "\n") != 3 { // header + 2 rows
		t.Fatalf("expected exactly 2 rows (+header) with --limit 2, got:\n%s", out)
	}
	if !strings.Contains(out, "two") || !strings.Contains(out, "three") || strings.Contains(out, "one") {
		t.Fatalf("expected --limit 2 to keep the 2 most recent events, got:\n%s", out)
	}
}

// TestLog_FollowPrintsExistingThenNewEvents is the end-to-end BDD scenario
// for `damping log --follow`: existing matching events print immediately,
// and an event appended while --follow is still running shows up without
// restarting the command — see features/audit_log.feature.
func TestLog_FollowPrintsExistingThenNewEvents(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	origInterval := logFollowPollInterval
	logFollowPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { logFollowPollInterval = origInterval })

	existingStdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"/proc/self/root/existing rm -rf /"}}`
	if _, _, err := run(t, existingStdin, "hook", "pretooluse"); !isExitCodeError(err, new(*ExitCodeError)) {
		t.Fatalf("expected the pre-existing event's hook call to hard-deny, got %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stdout, stderr, done := startLogFollow(t, ctx, "log", "--follow")

	// Wait for the follow-mode notice rather than a fixed sleep — proves
	// the initial batch has printed and the poll loop has started, without
	// tuning this test to a specific poll-interval/sleep-duration ratio
	// that could be flaky on a slower or more loaded machine.
	waitForContains(t, stderr, "Watching for new events", 1*time.Second)
	if !strings.Contains(stdout.String(), "existing") {
		t.Fatalf("expected the pre-existing event in the initial batch, got:\n%s", stdout.String())
	}

	// Appended directly via audit.Writer rather than another
	// run(t, ..., "hook", "pretooluse") call: NewRootCmd registers --config
	// against root.go's package-level configFlag var, so a second
	// concurrent NewRootCmd() call from this goroutine while the follow
	// goroutine's own NewRootCmd() call is in flight is racy — a
	// pre-existing test-harness limitation unrelated to what this test
	// actually exercises.
	auditPath, err := paths.Audit()
	if err != nil {
		t.Fatalf("resolving audit path: %v", err)
	}
	newEvent := event.New(event.NewID(), "s1", "claude-code", event.ChannelCLI, event.ActionShellExec,
		"/proc/self/root/newone rm -rf /", "/proc/self/root/newone rm -rf /",
		decision.Decision{Verdict: decision.Deny, PolicyID: "destructive.proc_sandbox_bypass"})
	if err := audit.NewWriter(auditPath).Append(newEvent); err != nil {
		t.Fatalf("appending new event: %v", err)
	}

	waitForContains(t, stdout, "newone", 1*time.Second)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("log --follow: %v (stderr: %s)", err, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for `damping log --follow` to stop after context cancellation")
	}
}

// TestLog_FollowJSONKeepsStdoutPureNDJSON is a regression test found via
// manual UX testing of the real built binary: the "Watching for new
// events..." notice was originally written to stdout, which — in --json
// mode — corrupted what's supposed to be a clean newline-delimited JSON
// stream, breaking a `damping log --follow --json | jq` pipeline. Every
// non-empty stdout line in --json mode must parse as JSON.
func TestLog_FollowJSONKeepsStdoutPureNDJSON(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	origInterval := logFollowPollInterval
	logFollowPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { logFollowPollInterval = origInterval })

	existingStdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"/proc/self/root/existing rm -rf /"}}`
	if _, _, err := run(t, existingStdin, "hook", "pretooluse"); !isExitCodeError(err, new(*ExitCodeError)) {
		t.Fatalf("expected the pre-existing event's hook call to hard-deny, got %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stdout, stderr, done := startLogFollow(t, ctx, "log", "--follow", "--json")

	waitForContains(t, stderr, "Watching for new events", 1*time.Second)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("log --follow --json: %v (stderr: %s)", err, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for `damping log --follow --json` to stop")
	}

	for _, line := range strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("expected every stdout line in --json mode to be valid JSON, got invalid line %q: %v", line, err)
		}
	}
}

// TestLog_JSONEmptyResultsNoticeGoesToStderr is a regression test for a
// bug the BDD suite (cli/bdd's audit_log_test.go) caught: printEvents wrote
// "No audit events matched those filters." to stdout unconditionally, even
// in --json mode — a `damping log --json --follow` starting from an empty
// audit log fed that plain-text line straight into what's supposed to be a
// pure NDJSON stream, the exact same class of bug already fixed once for
// the "Watching for new events" notice.
func TestLog_JSONEmptyResultsNoticeGoesToStderr(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	stdout, stderr, err := run(t, "", "log", "--json")
	if err != nil {
		t.Fatalf("log --json: %v", err)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("expected empty stdout for zero results in --json mode, got:\n%s", stdout)
	}
	if !strings.Contains(stderr, "No audit events matched those filters.") {
		t.Fatalf("expected the empty-results notice on stderr, got:\n%s", stderr)
	}
}

// TestLog_TableMarksDegradedEvents is a regression test for a real UX gap
// found via manually walking through the actual built binary's first-run
// experience: `damping doctor` clearly warns about degraded events, but a
// degraded event's Outcome() is still a plain "allow" (Degraded is a
// separate flag, not its own verdict), so `damping log`'s default table —
// the more natural first place a human would look — rendered it
// identically to a genuine policy allow, with no visual hint at all unless
// you already knew to pass --json or --outcome degraded.
func TestLog_TableMarksDegradedEvents(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}

	auditPath, err := paths.Audit()
	if err != nil {
		t.Fatalf("resolving audit path: %v", err)
	}
	// Distinct actors so each event's row can be picked out individually —
	// a review noted the original version of this test only ever appended
	// one degraded event, so a regression that marked *every* row
	// "(degraded)" regardless of the flag (e.g. hardcoding the suffix,
	// or reading the wrong field) would have slipped through undetected.
	degraded := event.New(event.NewID(), "s1", "claude-code", event.ChannelCLI, event.ActionShellExec,
		"", "", decision.Decision{Verdict: decision.Allow, Degraded: true, Reason: "simulated internal failure"})
	if err := audit.NewWriter(auditPath).Append(degraded); err != nil {
		t.Fatalf("appending degraded event: %v", err)
	}
	plain := event.New(event.NewID(), "s2", "cursor", event.ChannelCLI, event.ActionShellExec,
		"", "", decision.Decision{Verdict: decision.Allow, Reason: "genuine policy allow"})
	if err := audit.NewWriter(auditPath).Append(plain); err != nil {
		t.Fatalf("appending plain event: %v", err)
	}

	out, _, err := run(t, "", "log")
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	if !strings.Contains(out, "allow (degraded)") {
		t.Fatalf("expected the degraded event's row to be visually marked in the plain-table view, got:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "cursor") && strings.Contains(line, "(degraded)") {
			t.Fatalf("expected the genuinely non-degraded event's row to NOT be marked (degraded), got:\n%s", out)
		}
	}
}

func TestLog_ShowPrintsFullEvent(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	stdin := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"/proc/self/root/usr/bin/npx rm -rf /"}}`
	if _, _, err := run(t, stdin, "hook", "pretooluse"); !isExitCodeError(err, new(*ExitCodeError)) {
		t.Fatalf("expected a hard deny, got %v", err)
	}

	listOut, _, err := run(t, "", "log", "--json")
	if err != nil {
		t.Fatalf("log --json: %v", err)
	}
	var e struct {
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal([]byte(strings.SplitN(listOut, "\n", 2)[0]), &e); err != nil {
		t.Fatalf("parsing --json output: %v", err)
	}

	showOut, _, err := run(t, "", "log", "show", e.EventID)
	if err != nil {
		t.Fatalf("log show: %v", err)
	}
	if !strings.Contains(showOut, e.EventID) || !strings.Contains(showOut, "proc_sandbox_bypass") {
		t.Fatalf("expected the full event JSON including the matched rule, got:\n%s", showOut)
	}
}

func TestLog_ShowUnknownEventIDErrors(t *testing.T) {
	setupTestEnv(t)
	if _, _, err := run(t, "", "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, _, err := run(t, "", "log", "show", "evt_doesnotexist"); err == nil {
		t.Fatal("expected an error for an unknown event_id")
	}
}

// isExitCodeError is a small helper so tests can assert both "is this an
// ExitCodeError" and, via the caller checking exitErr.Code afterwards, which
// code — errors.As needs an addressable **ExitCodeError target.
func isExitCodeError(err error, target **ExitCodeError) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*ExitCodeError)
	if !ok {
		return false
	}
	*target = e
	return true
}
