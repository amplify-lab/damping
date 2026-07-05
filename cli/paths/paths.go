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
