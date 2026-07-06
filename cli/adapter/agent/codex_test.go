package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallCodexHook_OnMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")

	if err := InstallCodexHook(path, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	has, err := HasCodexHook(path)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !has {
		t.Fatal("expected the hook to be registered after install")
	}
}

// TestInstallCodexHook_PreservesExistingContent proves Codex's hooks.json
// keeps any other content untouched — mirroring
// TestInstallClaudeCodeHook_PreservesExistingContent, since both share
// pretooluse_hook.go's implementation.
func TestInstallCodexHook_PreservesExistingContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	initial := `{"hooks":{"PreToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"some-other-tool"}]}]}}`
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := InstallCodexHook(path, false); err != nil {
		t.Fatalf("install: %v", err)
	}

	var raw map[string]any
	data, err := os.ReadFile(path) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	hooks := raw["hooks"].(map[string]any)
	preToolUse := hooks["PreToolUse"].([]any)
	if len(preToolUse) != 2 {
		t.Fatalf("expected the pre-existing Edit-matcher entry plus Damping's own Bash entry, got %d entries: %v", len(preToolUse), preToolUse)
	}
}

func TestInstallCodexHook_IdempotentWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := InstallCodexHook(path, false); err != nil {
		t.Fatalf("first install: %v", err)
	}
	if err := InstallCodexHook(path, false); err != nil {
		t.Fatalf("second install: %v", err)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	preToolUse := raw["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(preToolUse) != 1 {
		t.Fatalf("expected exactly one entry after two no-force installs, got %d", len(preToolUse))
	}
}

// TestInstallCodexHook_NoVersionFieldRequired is a regression guard against
// accidentally carrying Cursor's required top-level "version" field over
// to Codex — verified against developers.openai.com/codex/hooks that no
// such field exists in Codex's contract; adding one unconditionally would
// be a no-op at best, but asserting its absence catches a copy-paste
// mistake from cursor.go instead of silently tolerating it.
func TestInstallCodexHook_NoVersionFieldRequired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := InstallCodexHook(path, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, has := raw["version"]; has {
		t.Fatal("Codex's hooks.json has no documented \"version\" requirement — did not expect one to be written")
	}
}

func TestHasCodexHook_FalseWhenRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := InstallCodexHook(path, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	has, err := HasCodexHook(path)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if has {
		t.Fatal("expected HasCodexHook to report false once the file was wiped")
	}
}
