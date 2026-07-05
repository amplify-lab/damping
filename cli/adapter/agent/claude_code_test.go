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

// TestInstallClaudeCodeHook_ForcePreservesOtherMatchersPreToolUseEntries is
// a regression test for a real bug: force mode used to discard the entire
// PreToolUse array (`preToolUse = []any{entry}`), silently deleting any
// hook the user configured for a matcher other than Damping's own ("Bash")
// — e.g. a "Write" or "Edit" matcher entry — the moment `damping init
// --force` ran. Force should only replace Bash-matcher entries.
func TestInstallClaudeCodeHook_ForcePreservesOtherMatchersPreToolUseEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	existing := `{"hooks": {"PreToolUse": [
		{"matcher": "Write", "hooks": [{"type": "command", "command": "some-other-tool"}]},
		{"matcher": "Bash", "hooks": [{"type": "command", "command": "damping hook pretooluse"}]}
	]}}`
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := InstallClaudeCodeHook(path, true); err != nil {
		t.Fatalf("install --force: %v", err)
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

	var sawWriteMatcher, sawBashMatcher int
	for _, raw := range preToolUse {
		entry := raw.(map[string]any)
		switch entry["matcher"] {
		case "Write":
			sawWriteMatcher++
		case "Bash":
			sawBashMatcher++
		}
	}
	if sawWriteMatcher != 1 {
		t.Fatalf("expected the unrelated Write-matcher entry to survive --force, got %d Write entries (all entries: %+v)", sawWriteMatcher, preToolUse)
	}
	if sawBashMatcher != 1 {
		t.Fatalf("expected exactly one Bash-matcher entry after --force, got %d", sawBashMatcher)
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
