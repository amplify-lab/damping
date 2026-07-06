package agent

// Codex CLI's hooks.json uses the exact same
// {"hooks":{"PreToolUse":[{"matcher":...,"hooks":[{"type":"command",
// "command":...}]}]}} shape as Claude Code's settings.json — verified
// against developers.openai.com/codex/hooks — with no required top-level
// "version" field the way Cursor's contract has. See
// pretooluse_hook.go for the shared implementation both agents use.
//
// Codex's own PreToolUse stdin payload is otherwise near-identical to
// Claude Code's (same hook_event_name value, same tool_input.command
// nesting) but includes turn_id/tool_use_id fields Claude Code's payload
// does not send — cli/cmd/hook.go uses that to tell the two apart at
// runtime, since hook_event_name alone can't (see hookInput's doc comment
// there).

const codexMatcher = "Bash"

// InstallCodexHook idempotently adds Damping's PreToolUse hook to a Codex
// hooks.json, preserving any other content in the file.
func InstallCodexHook(hooksPath string, force bool) error {
	return installPreToolUseHook(hooksPath, codexMatcher, force)
}

// HasCodexHook reports whether the hooks file already registers Damping's
// hook — used by `damping doctor` to detect removal since the last check.
func HasCodexHook(hooksPath string) (bool, error) {
	return hasPreToolUseHook(hooksPath, codexMatcher)
}
