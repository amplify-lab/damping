// Package agent installs and detects Damping's hook registration inside
// each supported AI coding agent's own settings file. See
// docs/cli-reference.md §11 for the verified Claude Code contract this
// targets; the Cursor schema in cursor.go is a best-effort approximation —
// see the comment there.
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// HookCommand is what damping registers as the hook entrypoint. Kept as a
// var (not a const) so tests can point it at a build-under-test binary.
var HookCommand = "damping hook pretooluse"

const claudeCodeMatcher = "Bash"

// InstallClaudeCodeHook idempotently adds Damping's PreToolUse hook to a
// Claude Code settings.json, preserving any other content in the file. It
// is safe to call repeatedly — it will not duplicate an existing entry for
// the same command+matcher unless force is true, in which case it replaces
// the PreToolUse/Bash entry list wholesale.
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
		preToolUse = []any{entry}
	} else {
		preToolUse = append(preToolUse, entry)
	}

	hooks["PreToolUse"] = preToolUse
	settings["hooks"] = hooks
	return writeJSONObject(settingsPath, settings)
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

func readJSONObject(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agent: reading %s: %w", path, err)
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("agent: parsing %s: %w", path, err)
	}
	return obj, nil
}

func writeJSONObject(path string, obj map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("agent: creating %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encoding %s: %w", path, err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("agent: writing %s: %w", path, err)
	}
	return nil
}
