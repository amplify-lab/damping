package agent

import (
	"path/filepath"
	"testing"
)

func TestInstallCursorHook_OnMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := InstallCursorHook(path, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	has, err := HasCursorHook(path)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !has {
		t.Fatal("expected hook to be registered after install")
	}
}

func TestInstallCursorHook_IdempotentWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := InstallCursorHook(path, false); err != nil {
		t.Fatal(err)
	}
	if err := InstallCursorHook(path, false); err != nil {
		t.Fatal(err)
	}
	root, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := root["hooks"].(map[string]any)[cursorEvent].([]any)
	if len(entries) != 1 {
		t.Fatalf("expected exactly one entry after calling install twice, got %d", len(entries))
	}
}
