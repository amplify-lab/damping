// Package bdd — see dangerous_command_test.go's doc comment for the overall
// approach. This file wires features/self_update.feature: `damping
// update`'s self-update-check semantics, plus the DAMPING_NO_UPDATE_CHECK
// split documented on update.Check and update.ForceCheck (the env var only
// silences the passive background notice other commands print, never an
// explicit, human-typed `damping update`). Deliberately scoped to what's
// fully deterministic without live network access — see the feature file's
// own header comment.
package bdd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/amplify-lab/damping/cli/cmd"
	"github.com/amplify-lab/damping/cli/paths"
)

func selfUpdateFeaturePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "features", "self_update.feature")
}

type selfUpdateWorld struct {
	stdout, stderr string
	runErr         error
}

// seedUpdateCache writes cli/update's on-disk cache file directly. Same
// shape as update.cacheState, duplicated here because that type is
// unexported and this package can't reach it — mirrors
// cli/cmd/cmd_test.go's own writeUpdateCache helper for the identical
// reason.
func seedUpdateCache(t *testing.T, latest string) {
	t.Helper()
	path, err := paths.UpdateCheck()
	if err != nil {
		t.Fatalf("paths.UpdateCheck: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cache := struct {
		Latest    string    `json:"latest"`
		CheckedAt time.Time `json:"checked_at"`
	}{Latest: latest, CheckedAt: time.Now()}
	data, err := json.Marshal(cache)
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}
}

func TestFeatures_SelfUpdate(t *testing.T) {
	// A fixed current version for every scenario in this suite, so seeded
	// cache values ("the latest" / "a newer version") have an unambiguous
	// meaning. Restored once, after the whole suite finishes, since godog
	// scenarios in one suite.Run() execute sequentially, not concurrently.
	prevVersion := cmd.Version
	cmd.Version = "v0.5.0"
	t.Cleanup(func() { cmd.Version = prevVersion })

	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			w := &selfUpdateWorld{}
			sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
				*w = selfUpdateWorld{}
				return ctx, nil
			})

			sc.Given(`^Damping is running with the default policy$`, func() error {
				dir := t.TempDir()
				t.Setenv("DAMPING_HOME", filepath.Join(dir, "damping-home"))
				t.Setenv("DAMPING_CLAUDE_SETTINGS", filepath.Join(dir, "claude", "settings.json"))
				t.Setenv("DAMPING_CURSOR_HOOKS", filepath.Join(dir, "cursor", "hooks.json"))
				t.Setenv("DAMPING_CODEX_HOOKS", filepath.Join(dir, "codex", "hooks.json"))
				// Ambient default for every scenario below — init's own
				// background notice must not make a real network call
				// before a scenario gets a chance to seed the cache.
				// Scenarios that need it unset override this explicitly.
				t.Setenv("DAMPING_NO_UPDATE_CHECK", "1")
				_, _, err := runDampingCommand("", "init")
				return err
			})

			sc.Given(`^the update cache reports the current version is the latest$`, func() error {
				seedUpdateCache(t, "v0.5.0")
				return nil
			})
			sc.Given(`^the update cache reports a newer version is available$`, func() error {
				seedUpdateCache(t, "v0.6.0")
				return nil
			})
			sc.Given(`^DAMPING_NO_UPDATE_CHECK is set$`, func() error {
				t.Setenv("DAMPING_NO_UPDATE_CHECK", "1")
				return nil
			})
			sc.Given(`^the install location needs elevated privileges$`, func() error {
				// Mirrors cli/cmd/cmd_test.go's nonWritableInstallDir: points
				// DAMPING_INSTALL_DIR inside a path component that's already
				// a regular file, so the writability probe can never
				// succeed regardless of the running user's privileges. Keeps
				// `damping update` on the informational branch, so it never
				// actually execs the real curl-pipe-sh installer here.
				parent := t.TempDir()
				blocker := filepath.Join(parent, "blocked-by-a-file")
				if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
					return err
				}
				t.Setenv("DAMPING_INSTALL_DIR", filepath.Join(blocker, "sub", "damping"))
				return nil
			})

			sc.When(`^the user runs "([^"]*)"$`, func(cmdline string) error {
				fields := strings.Fields(cmdline)
				w.stdout, w.stderr, w.runErr = runDampingCommand("", fields[1:]...)
				return nil
			})

			sc.Then(`^the output should say damping is already up to date$`, func() error {
				if w.runErr != nil {
					return fmt.Errorf("damping update: %w (stdout: %s)", w.runErr, w.stdout)
				}
				if !strings.Contains(w.stdout, "already up to date") {
					return fmt.Errorf("expected an already-up-to-date message, got: %s", w.stdout)
				}
				return nil
			})
			sc.Then(`^the output should not mention an available update$`, func() error {
				if w.runErr != nil {
					return fmt.Errorf("damping status: %w (stdout: %s)", w.runErr, w.stdout)
				}
				if strings.Contains(w.stdout, "is available") || strings.Contains(w.stderr, "is available") {
					return fmt.Errorf("expected no update notice with DAMPING_NO_UPDATE_CHECK set, got stdout=%q stderr=%q", w.stdout, w.stderr)
				}
				return nil
			})
			sc.Then(`^the output should report the available update, not a false already-up-to-date$`, func() error {
				if w.runErr != nil {
					return fmt.Errorf("damping update: %w (stdout: %s)", w.runErr, w.stdout)
				}
				if strings.Contains(w.stdout, "already up to date") {
					return fmt.Errorf("expected damping update to still report the real available update despite DAMPING_NO_UPDATE_CHECK, got: %s", w.stdout)
				}
				if !strings.Contains(w.stdout, "v0.6.0") {
					return fmt.Errorf("expected the available version v0.6.0 mentioned, got: %s", w.stdout)
				}
				return nil
			})
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{selfUpdateFeaturePath(t)},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
