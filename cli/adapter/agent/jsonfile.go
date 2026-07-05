package agent

// Generic JSON-object file read/write, shared by claude_code.go and
// cursor.go — neither agent's hook file format is special here, so this
// lives in its own file rather than inside one agent's, where a reader
// might mistake it for Claude-Code-specific logic.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func readJSONObject(path string) (map[string]any, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the local user's own agent hook config file (~/.claude/settings.json or ~/.cursor/hooks.json), not an attacker-influenced path
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
	// 0o750/0o600, not the more common 0o755/0o644: these mode bits only
	// ever take effect the first time damping itself creates this
	// directory/file (an existing one keeps whatever permissions it
	// already had, since neither MkdirAll nor WriteFile widen an existing
	// path's mode) — found via gosec's G301/G306. Claude Code/Cursor run
	// as the same local user that ran `damping init`, so tightening away
	// group/other access doesn't affect their own read/write access at
	// all, only a hypothetical other local account's.
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("agent: creating %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encoding %s: %w", path, err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("agent: writing %s: %w", path, err)
	}
	return nil
}
