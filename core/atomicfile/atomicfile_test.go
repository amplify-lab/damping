package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWrite_NoTempFileLeftBehindOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := Write(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "out.txt" {
		t.Fatalf("expected exactly one file (out.txt, no leftover temp file), got %v", entries)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("expected file content %q, got %q", "hello", got)
	}
}

func TestWrite_SetsRequestedPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	if err := Write(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %v", info.Mode().Perm())
	}
}
