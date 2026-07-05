//go:build unix

package atomicfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWrite_LeavesOriginalContentIntactOnPartialWriteFailure is the
// regression test for the actual bug this package exists to fix: a plain
// os.WriteFile truncates the destination before the new content lands, so a
// crash/disk-full/RLIMIT-exceeded failure partway through leaves the
// destination corrupted — neither the old content nor the new content.
// Forces a real partial-write failure via RLIMIT_FSIZE (the same failure
// class as a real disk-full condition) and confirms the destination file is
// completely untouched, not truncated or garbled, because the failure hits
// the temp file before any rename occurs. Unix-only: RLIMIT_FSIZE has no
// Windows equivalent in the syscall package.
func TestWrite_LeavesOriginalContentIntactOnPartialWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	original := []byte(`{"original":"content that must survive"}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &rlimit); err != nil {
		t.Skipf("cannot read RLIMIT_FSIZE, skipping: %v", err)
	}
	restore := rlimit
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &restore) })
	limited := syscall.Rlimit{Cur: 10, Max: restore.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
		t.Skipf("cannot lower RLIMIT_FSIZE, skipping: %v", err)
	}

	big := make([]byte, 4096)
	err := Write(path, big, 0o600)
	if err == nil {
		t.Fatal("expected the oversized write to fail under the lowered RLIMIT_FSIZE")
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != string(original) {
		t.Fatalf("expected original content to survive a failed write untouched, got %q", got)
	}
}
