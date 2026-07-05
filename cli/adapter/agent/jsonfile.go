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
