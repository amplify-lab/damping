//go:build unix

package agent

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWriteJSONObject_PreservesExistingContentOnPartialWriteFailure is a
// regression test for a real bug: writeJSONObject used to call a plain
// os.WriteFile directly against the destination path — an external agent's
// own settings file (all of it, not just Damping's hook entry) — which
// truncates the file before the new content lands. A crash, disk-full
// condition, or Ctrl-C during `damping init`'s hook-install step could
// leave Claude Code's/Cursor's entire config corrupted, not merely fail to
// register the hook. Now delegates to core/atomicfile.Write, so a forced
// partial-write failure (via RLIMIT_FSIZE, the same failure class as a
// real disk-full condition) must leave the original file completely
// untouched, exactly matching InstallClaudeCodeHook's/InstallCursorHook's
// own "preserving any other content in the file" doc comment.
func TestWriteJSONObject_PreservesExistingContentOnPartialWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	original := `{"someOtherTool":{"config":"MUST_SURVIVE_MARKER"}}` + "\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
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

	big := make(map[string]any, 1)
	filler := make([]byte, 4096)
	big["filler"] = string(filler)
	err := writeJSONObject(path, big)
	if err == nil {
		t.Fatal("expected the oversized write to fail under the lowered RLIMIT_FSIZE")
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != original {
		t.Fatalf("expected the original settings content to survive a failed write untouched, got %q", got)
	}
}
