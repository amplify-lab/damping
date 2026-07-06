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

// claudeCodeMatcher covers Bash plus the three Write-family tool calls the
// 2026-07 non-Bash attack-surface expansion added support for (see
// core/policy/rules_configwrite.go, cli/cmd/hook.go). Claude Code's matcher
// field accepts a regex, and "|" alternation for an exact set of tool names
// is documented, verified behavior (see docs/cli-reference.md §11) — one
// PreToolUse entry covering all four is simpler than four separate entries
// and both are equivalent from Claude Code's perspective.
//
// Upgrade note: a settings.json written by a Damping version before this
// change has a standalone `{"matcher": "Bash", ...}` entry. Re-running
// `damping init` (with or without --force) does not retroactively widen
// that old entry in place — matcher-based dedup/replacement below is an
// exact string match (see removeMatcherEntries), so the old "Bash"-only
// entry and the new "Bash|Write|Edit|MultiEdit" entry can briefly coexist
// after an upgrade. Harmless (both invoke the same idempotent `damping hook
// pretooluse`, and the old entry is a strict subset of the new one's
// coverage) but not auto-cleaned up — not worth a migration path for a
// pre-1.0 individual-tier CLI with no installed base yet to migrate.
const claudeCodeMatcher = "Bash|Write|Edit|MultiEdit"

// InstallClaudeCodeHook idempotently adds Damping's PreToolUse hook to a
// Claude Code settings.json, preserving any other content in the file —
// including, under force, any PreToolUse entry scoped to a matcher other
// than Damping's own (claudeCodeMatcher). It is safe to call repeatedly —
// it will not duplicate an existing entry for the same command+matcher
// unless force is true, in which case it replaces only Damping's own
// matcher's entries, not the whole PreToolUse array (a prior version
// discarded every matcher's entries under force — e.g. a user's own
// Write/Edit hooks — found via review).
func InstallClaudeCodeHook(settingsPath string, force bool) error {
	return installPreToolUseHook(settingsPath, claudeCodeMatcher, force)
}

// HasClaudeCodeHook reports whether the settings file already registers
// Damping's hook — used by `damping doctor` to detect removal since the
// last check (see docs/threat-model.md §4).
func HasClaudeCodeHook(settingsPath string) (bool, error) {
	return hasPreToolUseHook(settingsPath, claudeCodeMatcher)
}
