package agent

import (
	"os"
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

// TestInstallCursorHook_WritesRequiredVersionField is a regression test for
// a real silent-total-bypass bug: Cursor's real hooks.json schema requires
// a top-level "version" field (https://cursor.com/docs/hooks), and real
// Cursor releases reject the entire file without it — silently disabling
// every hook in it, including Damping's, while damping doctor/status
// (which only re-parsed what Damping itself wrote) would still report the
// hook as healthy. InstallCursorHook never wrote this field at all before
// this fix.
func TestInstallCursorHook_WritesRequiredVersionField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := InstallCursorHook(path, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	root, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := root["version"]
	if !ok {
		t.Fatal("expected a top-level \"version\" field, found none")
	}
	if n, ok := v.(float64); !ok || n != 1 {
		t.Fatalf("expected version to be the number 1, got %#v", v)
	}
}

// TestHasCursorHook_FalseWhenVersionFieldMissing is the detection-side half
// of the same fix: a hooks.json with the hook entry present but the
// required "version" field missing (e.g. a file installed before this fix
// landed, or hand-edited) must be reported as unregistered, not healthy —
// Cursor may silently refuse to load that whole file.
func TestHasCursorHook_FalseWhenVersionFieldMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	pre := `{"hooks":{"beforeShellExecution":[{"command":"damping hook pretooluse"}]}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	has, err := HasCursorHook(path)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("expected a hooks.json missing the required \"version\" field to be reported as unregistered")
	}
}

// TestInstallCursorHook_HealsMissingVersionFieldWithoutForce proves the fix
// self-heals an existing installation from before this bug was fixed: even
// without --force, a hooks.json with the entry already present but no
// "version" field gets the field added on the next install call, without
// duplicating the hook entry.
func TestInstallCursorHook_HealsMissingVersionFieldWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	pre := `{"hooks":{"beforeShellExecution":[{"command":"damping hook pretooluse"}]}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallCursorHook(path, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	root, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := root["version"]; !ok {
		t.Fatal("expected the missing \"version\" field to be healed")
	}
	entries := root["hooks"].(map[string]any)[cursorEvent].([]any)
	if len(entries) != 1 {
		t.Fatalf("expected the hook entry to still appear exactly once (not duplicated), got %d", len(entries))
	}
}

// TestInstallCursorHook_PreservesExistingVersionValue proves the fix never
// overwrites a version value that's already present, force or not.
func TestInstallCursorHook_PreservesExistingVersionValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	pre := `{"version":2,"hooks":{}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InstallCursorHook(path, true); err != nil {
		t.Fatalf("install: %v", err)
	}
	root, err := readJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	if v := root["version"]; v != float64(2) {
		t.Fatalf("expected the existing version value 2 to be preserved, got %#v", v)
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
