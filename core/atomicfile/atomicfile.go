// Package atomicfile provides a single crash-safe file write, shared by
// every place in this codebase that overwrites an existing config file in
// place: core/policy.AppendAlwaysPattern (the policy YAML) and
// cli/adapter/agent's hook installers (an external agent's own
// settings.json/hooks.json — found missing this same protection via
// review, after the policy file had already needed it once).
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write writes data to path by creating a temp file in the same directory
// (so the final rename is on the same filesystem, which POSIX guarantees is
// atomic), setting perm, and renaming it into place — instead of writing
// path directly, which a plain os.WriteFile implements as open-with-
// O_TRUNC-then-write: the destination is truncated before the new content
// lands, so a crash, OOM-kill, or disk-full condition mid-write leaves
// whatever file was at path corrupted or empty, not simply "not yet
// updated." This does not by itself serialize concurrent *writers* (two
// processes writing to the same path at once can still race, with one
// update winning), but it does guarantee every reader always sees either
// the old complete file or the new complete file, never a partial one.
func Write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".damping-atomic-*.tmp")
	if err != nil {
		return fmt.Errorf("atomicfile: creating temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // already returning the real error below; best-effort cleanup
		return fmt.Errorf("atomicfile: writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicfile: closing temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("atomicfile: setting permissions on temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("atomicfile: renaming temp file into place: %w", err)
	}
	return nil
}
