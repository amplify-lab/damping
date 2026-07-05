package agent

// NOTE ON ACCURACY: Cursor's hooks.json schema is documented at
// https://cursor.com/docs/hooks (verified during planning to exist and use
// beforeShellExecution / beforeMCPExecution / etc. as event names — see
// docs/00-統一開發計畫（定案版）.md §四修正二). The exact nested shape below
// is a best-effort approximation based on that research and should be
// re-verified against the live docs before this is trusted as ground truth
// — flagging this honestly rather than presenting a guess as a fact.

const cursorEvent = "beforeShellExecution"

// InstallCursorHook idempotently adds Damping's beforeShellExecution hook to
// a Cursor hooks.json, preserving any other content in the file.
func InstallCursorHook(hooksPath string, force bool) error {
	root, err := readJSONObject(hooksPath)
	if err != nil {
		return err
	}

	hooks, _ := root["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	entries, _ := hooks[cursorEvent].([]any)

	if !force && hasCursorHookEntry(entries) {
		return nil
	}

	entry := map[string]any{"command": HookCommand}
	if force {
		entries = []any{entry}
	} else {
		entries = append(entries, entry)
	}

	hooks[cursorEvent] = entries
	root["hooks"] = hooks
	return writeJSONObject(hooksPath, root)
}

// HasCursorHook reports whether the hooks file already registers Damping's
// hook — used by `damping doctor`.
func HasCursorHook(hooksPath string) (bool, error) {
	root, err := readJSONObject(hooksPath)
	if err != nil {
		return false, err
	}
	hooks, _ := root["hooks"].(map[string]any)
	entries, _ := hooks[cursorEvent].([]any)
	return hasCursorHookEntry(entries), nil
}

func hasCursorHookEntry(entries []any) bool {
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if ok && entry["command"] == HookCommand {
			return true
		}
	}
	return false
}
