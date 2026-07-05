package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
