package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amplify-lab/damping/cli/ui"
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
	// Deliberately skip `init` — no hooks have ever been registered.
	statusOut, _, err := run(t, "", "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(statusOut, "damping init") {
		t.Fatalf("expected a hint to run `damping init` when no agent is registered, got: %s", statusOut)
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
