package agent

// Cursor's hooks.json schema is documented at https://cursor.com/docs/hooks.
// The registration shape here (hooks.json's own structure — event name,
// hook entry list, command string) was re-verified via that documentation:
// a review found cli/cmd/hook.go's stdin-payload decoding had never
// actually been implemented for Cursor at all despite this file installing
// the hook correctly — every real Cursor command was silently allowed with
// no policy evaluation. See hookInput's doc comment in cli/cmd/hook.go for
// the confirmed beforeShellExecution stdin shape (hook_event_name,
// conversation_id, generation_id, command, cwd, workspace_roots) and
// response contract (exit code 2 blocks, same as {"permission":"deny"}).

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
