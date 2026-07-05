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
//
// A later review found that "re-verification" had itself missed a real,
// severe gap: Cursor's docs also state hooks.json's top-level "version"
// field is required ("Config schema version... All configuration files
// should include \"version\": 1 at root"), and real Cursor releases enforce
// this as fatal for the *whole file* — a hooks.json missing "version"
// fails to load at all, silently disabling every hook it contains,
// including Damping's, while damping doctor/status (which only re-parses
// what Damping itself wrote) would still report the hook as registered.
// The exact same silent-total-bypass class as the stdin-decoding bug above.
// Fixed below by always ensuring "version" is present.

const cursorEvent = "beforeShellExecution"

// InstallCursorHook idempotently adds Damping's beforeShellExecution hook to
// a Cursor hooks.json, preserving any other content in the file (including
// an existing "version" value, if the file already has one — only ever set
// to 1 when the field is missing entirely, never overwritten).
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

	_, hasVersion := root["version"]
	alreadyRegistered := hasCursorHookEntry(entries)

	if !force && alreadyRegistered && hasVersion {
		return nil
	}

	if !hasVersion {
		root["version"] = 1
	}

	entry := map[string]any{"command": HookCommand}
	switch {
	case force:
		entries = []any{entry}
	case !alreadyRegistered:
		entries = append(entries, entry)
	}

	hooks[cursorEvent] = entries
	root["hooks"] = hooks
	return writeJSONObject(hooksPath, root)
}

// HasCursorHook reports whether the hooks file already registers Damping's
// hook AND has the top-level "version" field real Cursor releases require
// to load the file at all — used by `damping doctor`. A hooks.json with the
// entry present but "version" missing is reported as unregistered rather
// than healthy, since that's a file Cursor may silently refuse to load in
// its entirety (see InstallCursorHook's doc comment).
func HasCursorHook(hooksPath string) (bool, error) {
	root, err := readJSONObject(hooksPath)
	if err != nil {
		return false, err
	}
	if _, hasVersion := root["version"]; !hasVersion {
		return false, nil
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
