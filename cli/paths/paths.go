// Package paths centralizes where damping's on-disk state lives. Every path
// respects $DAMPING_HOME as an override so tests (and anyone debugging a
// broken install) can point at a throwaway directory instead of a real
// ~/.damping.
package paths

import (
	"os"
	"path/filepath"
)

// Home returns the damping state directory, defaulting to ~/.damping.
func Home() (string, error) {
	if v := os.Getenv("DAMPING_HOME"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".damping"), nil
}

// Policy returns the path to the active policy file.
func Policy() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "policy.yaml"), nil
}

// Audit returns the path to the local append-only audit log.
func Audit() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "audit.jsonl"), nil
}

// DisabledMarker returns the path to the marker file `damping off` creates.
// Its presence means enforcement is off; see docs/cli-reference.md §6 and
// features/self_protection.feature.
func DisabledMarker() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "disabled"), nil
}

// DoctorState returns the path to doctor's small state file (last-known
// policy file hash, last-known hook registration state) used to detect
// tampering/removal between runs — see docs/threat-model.md §4 and §8.
func DoctorState() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "doctor-state.json"), nil
}

// ClaudeSettings returns where Claude Code's own hook config lives —
// $DAMPING_CLAUDE_SETTINGS if set (tests use this to point at a throwaway
// file), else the real ~/.claude/settings.json. Unlike the paths above this
// isn't under Home()/$DAMPING_HOME: it's a different tool's config file that
// damping only ever reads or edits, never owns.
func ClaudeSettings() string {
	if v := os.Getenv("DAMPING_CLAUDE_SETTINGS"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "settings.json")
}

// CursorHooks returns where Cursor's own hook config lives — see
// ClaudeSettings's doc comment, same reasoning with $DAMPING_CURSOR_HOOKS.
func CursorHooks() string {
	if v := os.Getenv("DAMPING_CURSOR_HOOKS"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cursor", "hooks.json")
}
