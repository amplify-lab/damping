package agent

// installPreToolUseHook implements the shared install logic for any agent
// whose hook config file uses the shape
// {"hooks":{"PreToolUse":[{"matcher":...,"hooks":[{"type":"command",
// "command":...}]}]}} — currently Claude Code (settings.json, mixed with
// unrelated settings) and Codex (a dedicated hooks.json) both use this
// exact shape, independently verified against each agent's own docs (see
// claude_code.go/codex.go). Cursor's shape differs (a flat
// beforeShellExecution list, plus a required top-level "version" field)
// and keeps its own implementation in cursor.go.
func installPreToolUseHook(path, matcher string, force bool) error {
	root, err := readJSONObject(path)
	if err != nil {
		return err
	}

	hooks, _ := root["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	preToolUse, _ := hooks["PreToolUse"].([]any)

	if !force && hasPreToolUseHookEntry(preToolUse, matcher) {
		return nil // already installed
	}

	entry := map[string]any{
		"matcher": matcher,
		"hooks": []any{
			map[string]any{"type": "command", "command": HookCommand},
		},
	}
	if force {
		preToolUse = append(removeMatcherEntries(preToolUse, matcher), entry)
	} else {
		preToolUse = append(preToolUse, entry)
	}

	hooks["PreToolUse"] = preToolUse
	root["hooks"] = hooks
	return writeJSONObject(path, root)
}

// hasPreToolUseHook reports whether path's PreToolUse array already
// registers Damping's hook under matcher.
func hasPreToolUseHook(path, matcher string) (bool, error) {
	root, err := readJSONObject(path)
	if err != nil {
		return false, err
	}
	hooks, _ := root["hooks"].(map[string]any)
	preToolUse, _ := hooks["PreToolUse"].([]any)
	return hasPreToolUseHookEntry(preToolUse, matcher), nil
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

func hasPreToolUseHookEntry(preToolUse []any, matcher string) bool {
	for _, raw := range preToolUse {
		entry, ok := raw.(map[string]any)
		if !ok || entry["matcher"] != matcher {
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
