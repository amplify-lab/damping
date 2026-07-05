package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestWriteJSONObject_CreatesRestrictivePermissions is a regression test
// found missing via adversarial review of the permission tightening in
// jsonfile.go (0o755/0o644 -> 0o750/0o600): nothing previously asserted the
// actual mode bits, only the JSON content, so a future accidental revert of
// those constants would go unnoticed. Windows has no meaningful POSIX mode
// bits to assert on, so this only runs where it means something.
func TestWriteJSONObject_CreatesRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions don't apply on windows")
	}

	dir := filepath.Join(t.TempDir(), "newly-created-dir")
	path := filepath.Join(dir, "settings.json")

	if err := writeJSONObject(path, map[string]any{"a": 1}); err != nil {
		t.Fatalf("writeJSONObject: %v", err)
	}

	// Checked as "no bits set beyond the requested mode" rather than an
	// exact match: the process umask can only ever restrict further, never
	// loosen, so this stays reliable across environments with a stricter
	// umask than this one's (022) while still catching the actual
	// regression this guards against — reverting to the old 0o755/0o644
	// sets bits (e.g. "other execute"/"other read") that fall outside
	// 0o750/0o600 regardless of umask.
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got&^0o750 != 0 {
		t.Errorf("expected the created directory's permissions to be at most 0750, got %o", got)
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got&^0o600 != 0 {
		t.Errorf("expected the created file's permissions to be at most 0600, got %o", got)
	}
}
