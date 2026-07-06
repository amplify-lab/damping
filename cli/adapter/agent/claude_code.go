// Package agent installs and detects Damping's hook registration inside
// each supported AI coding agent's own settings file. See
// docs/cli-reference.md §11 for the verified Claude Code contract this
// targets; see cursor.go's own comment for the verified Cursor contract,
// including the required top-level "version" field a prior review found
// missing; see codex.go for Codex, which shares this file's exact
// PreToolUse-array shape (pretooluse_hook.go).
package agent

// HookCommand is what damping registers as the hook entrypoint. Kept as a
// var (not a const) so tests can point it at a build-under-test binary.
var HookCommand = "damping hook pretooluse"

const claudeCodeMatcher = "Bash"

// InstallClaudeCodeHook idempotently adds Damping's PreToolUse hook to a
// Claude Code settings.json, preserving any other content in the file —
// including, under force, any PreToolUse entry scoped to a matcher other
// than Damping's own ("Bash"). It is safe to call repeatedly — it will not
// duplicate an existing entry for the same command+matcher unless force is
// true, in which case it replaces only the Bash-matcher entries, not the
// whole PreToolUse array (a prior version discarded every matcher's
// entries under force — e.g. a user's own Write/Edit hooks — found via
// review).
func InstallClaudeCodeHook(settingsPath string, force bool) error {
	return installPreToolUseHook(settingsPath, claudeCodeMatcher, force)
}

// HasClaudeCodeHook reports whether the settings file already registers
// Damping's hook — used by `damping doctor` to detect removal since the
// last check (see docs/threat-model.md §4).
func HasClaudeCodeHook(settingsPath string) (bool, error) {
	return hasPreToolUseHook(settingsPath, claudeCodeMatcher)
}
