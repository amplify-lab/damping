package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallClaudeCodeHook_OnMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")

	if err := InstallClaudeCodeHook(path, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	has, err := HasClaudeCodeHook(path)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !has {
		t.Fatal("expected hook to be registered after install")
	}
}

func TestInstallClaudeCodeHook_PreservesExistingContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	existing := `{"some_other_setting": true, "hooks": {"PostToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "some-other-tool"}]}]}}`
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := InstallClaudeCodeHook(path, false); err != nil {
		t.Fatalf("install: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["some_other_setting"] != true {
		t.Fatal("expected unrelated settings to be preserved")
	}
	hooks := obj["hooks"].(map[string]any)
	if _, ok := hooks["PostToolUse"]; !ok {
		t.Fatal("expected an unrelated PostToolUse hook to be preserved")
	}
	if _, ok := hooks["PreToolUse"]; !ok {
		t.Fatal("expected PreToolUse hook to have been added")
	}
}

func TestInstallClaudeCodeHook_IdempotentWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := InstallClaudeCodeHook(path, false); err != nil {
		t.Fatal(err)
	}
	if err := InstallClaudeCodeHook(path, false); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatal(err)
	}
	preToolUse := obj["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(preToolUse) != 1 {
		t.Fatalf("expected exactly one PreToolUse entry after calling install twice, got %d", len(preToolUse))
	}
}

func TestHasClaudeCodeHook_FalseWhenRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := InstallClaudeCodeHook(path, false); err != nil {
		t.Fatal(err)
	}
	// Simulate something other than `damping off` removing the hook — see
	// features/self_protection.feature "Hook removal outside damping off".
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	has, err := HasClaudeCodeHook(path)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("expected HasClaudeCodeHook to report false once the entry is gone")
	}
}
