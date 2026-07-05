// Package agent installs and detects Damping's hook registration inside
// each supported AI coding agent's own settings file. See
// docs/cli-reference.md §11 for the verified Claude Code contract this
// targets; see cursor.go's own comment for the verified Cursor contract,
// including the required top-level "version" field a prior review found
// missing.
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
	settings, err := readJSONObject(settingsPath)
	if err != nil {
		return err
	}

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	preToolUse, _ := hooks["PreToolUse"].([]any)

	if !force && hasClaudeHookEntry(preToolUse) {
		return nil // already installed
	}

	entry := map[string]any{
		"matcher": claudeCodeMatcher,
		"hooks": []any{
			map[string]any{"type": "command", "command": HookCommand},
		},
	}
	if force {
		preToolUse = append(removeMatcherEntries(preToolUse, claudeCodeMatcher), entry)
	} else {
		preToolUse = append(preToolUse, entry)
	}

	hooks["PreToolUse"] = preToolUse
	settings["hooks"] = hooks
	return writeJSONObject(settingsPath, settings)
}

// removeMatcherEntries drops every PreToolUse entry scoped to matcher,
// preserving entries for any other matcher (or malformed entries — a
// non-object element passes through untouched rather than being
// interpreted as "no matcher, drop it") in their original order.
func removeMatcherEntries(preToolUse []any, matcher string) []any {
	kept := make([]any, 0, len(preToolUse))
	for _, raw := range preToolUse {
		if m, ok := raw.(map[string]any); ok && m["matcher"] == matcher {
			continue
		}
		kept = append(kept, raw)
	}
	return kept
}

// HasClaudeCodeHook reports whether the settings file already registers
// Damping's hook — used by `damping doctor` to detect removal since the
// last check (see docs/threat-model.md §4).
func HasClaudeCodeHook(settingsPath string) (bool, error) {
	settings, err := readJSONObject(settingsPath)
	if err != nil {
		return false, err
	}
	hooks, _ := settings["hooks"].(map[string]any)
	preToolUse, _ := hooks["PreToolUse"].([]any)
	return hasClaudeHookEntry(preToolUse), nil
}

func hasClaudeHookEntry(preToolUse []any) bool {
	for _, raw := range preToolUse {
		entry, ok := raw.(map[string]any)
		if !ok || entry["matcher"] != claudeCodeMatcher {
			continue
		}
		hooksList, _ := entry["hooks"].([]any)
		for _, rawHook := range hooksList {
			h, ok := rawHook.(map[string]any)
			if ok && h["command"] == HookCommand {
				return true
			}
		}
	}
	return false
}
