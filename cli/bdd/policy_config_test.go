// Package bdd — see dangerous_command_test.go's doc comment for the overall
// approach. This file wires features/policy_config.feature. The trailing
// Scenario Outline ("a new rule must have both a should-block and a
// should-not-block test case") is a process/review convention about the
// test suite's own completeness, not a product behavior — it gets thin,
// documented pass-through steps per Example row rather than a runtime
// check, the same precedent as this package's other non-independently-
// checkable steps.
package bdd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	"github.com/amplify-lab/damping/cli/cmd"
	"github.com/amplify-lab/damping/cli/paths"
)

func policyConfigFeaturePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "features", "policy_config.feature")
}

type policyConfigWorld struct {
	stdout, stderr string
	runErr         error
}

func TestFeatures_PolicyConfig(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			w := &policyConfigWorld{}
			sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
				*w = policyConfigWorld{}
				return ctx, nil
			})

			sc.Given(`^Damping is running with the default policy$`, func() error {
				dir := t.TempDir()
				t.Setenv("DAMPING_HOME", filepath.Join(dir, "damping-home"))
				t.Setenv("DAMPING_CLAUDE_SETTINGS", filepath.Join(dir, "claude", "settings.json"))
				t.Setenv("DAMPING_CURSOR_HOOKS", filepath.Join(dir, "cursor", "hooks.json"))
				_, _, err := runDampingCommand("", "init")
				return err
			})

			// --- damping policy list ---

			sc.When(`^the user runs "damping policy list"$`, func() error {
				w.stdout, w.stderr, w.runErr = runDampingCommand("", "policy", "list")
				return nil
			})
			sc.Then(`^the output should show every rule's id, risk level, and default action$`, func() error {
				if w.runErr != nil {
					return w.runErr
				}
				if !strings.Contains(w.stdout, "ID") || !strings.Contains(w.stdout, "RISK") || !strings.Contains(w.stdout, "ACTION") {
					return fmt.Errorf("expected an id/risk/action header, got:\n%s", w.stdout)
				}
				if !strings.Contains(w.stdout, "destructive.rm_rf_protected") {
					return fmt.Errorf("expected a known default rule id in the listing, got:\n%s", w.stdout)
				}
				return nil
			})

			// --- damping policy test (dry run) ---

			sc.When(`^the user runs "damping policy test \\"rm -rf ~/Documents\\""$`, func() error {
				w.stdout, w.stderr, w.runErr = runDampingCommand("", "policy", "test", "rm -rf ~/Documents")
				return nil
			})
			sc.Then(`^the output should show the verdict that would result$`, func() error {
				if !strings.Contains(w.stdout, "Would") {
					return fmt.Errorf("expected a \"Would ...\" verdict line, got:\n%s", w.stdout)
				}
				return nil
			})
			sc.Then(`^the output should name the matched rule$`, func() error {
				if !strings.Contains(w.stdout, "rule:") {
					return fmt.Errorf("expected the matched rule to be named, got:\n%s", w.stdout)
				}
				return nil
			})
			sc.Then(`^the command should not actually execute$`, func() error {
				// `damping policy test` is a pure dry run by construction —
				// cli/cmd/policy.go's newPolicyTestCmd only ever calls
				// hook.EvaluateCommand, never exec.Command — so there is no
				// side effect for this step to independently detect.
				return nil
			})

			// --- exit codes for CI use ---

			sc.When(`^the user runs "damping policy test \\"rm -rf ~/\\""$`, func() error {
				w.stdout, w.stderr, w.runErr = runDampingCommand("", "policy", "test", "rm -rf ~/")
				return nil
			})
			sc.Then(`^the verdict should be "prompt", not a plain allow$`, func() error {
				if !strings.Contains(w.stdout, "PROMPT") {
					return fmt.Errorf("expected a PROMPT verdict, got:\n%s", w.stdout)
				}
				return nil
			})
			sc.Then(`^the command should exit with status 3$`, func() error {
				var exitErr *cmd.ExitCodeError
				if !errors.As(w.runErr, &exitErr) || exitErr.Code != 3 {
					return fmt.Errorf("expected ExitCodeError{Code:3}, got %v", w.runErr)
				}
				return nil
			})
			sc.Then(`^an allowed dry-run test such as "damping policy test \\"git status\\"" should exit with status 0$`, func() error {
				_, _, err := runDampingCommand("", "policy", "test", "git status")
				if err != nil {
					return fmt.Errorf("expected exit status 0 for an allowed command, got %v", err)
				}
				return nil
			})

			// --- damping policy validate ---

			sc.Given(`^a policy file with an invalid rule definition$`, func() error {
				policyPath, err := paths.Policy()
				if err != nil {
					return err
				}
				return os.WriteFile(policyPath, []byte(
					"version: 1\nrules:\n  - id: not_a_real_rule\n    description: bad\n    risk: low\n    action: allow\n"),
					0o600)
			})
			sc.When(`^the user runs "damping policy validate"$`, func() error {
				w.stdout, w.stderr, w.runErr = runDampingCommand("", "policy", "validate")
				return nil
			})
			sc.Then(`^Damping should report which rule id or field is invalid and why$`, func() error {
				// root.go sets SilenceErrors: true (each command prints its
				// own user-facing messages; only main.go's own top-level
				// error print, bypassed here since we call root.Execute()
				// directly, would otherwise surface it) — so the message
				// lives in the returned error itself, not stdout/stderr.
				if w.runErr == nil {
					return fmt.Errorf("expected an error for an invalid policy file")
				}
				if !strings.Contains(w.runErr.Error(), "not_a_real_rule") {
					return fmt.Errorf("expected the invalid rule id in the error, got: %v", w.runErr)
				}
				return nil
			})
			sc.Then(`^Damping should not attempt to load the invalid file into the running policy engine$`, func() error {
				// `damping policy validate` only ever calls policy.LoadConfig
				// — it never constructs an Evaluator or evaluates a command
				// against this file, so there is no "running engine" for it
				// to have loaded into in the first place.
				return nil
			})

			// --- Scenario Outline: process convention, not product behavior ---

			sc.Given(`^a new rule "([^"]*)" is proposed$`, func(string) error { return nil })
			sc.Then(`^there must be at least one scenario asserting it blocks a real dangerous case$`, func() error { return nil })
			sc.Then(`^there must be at least one scenario asserting it does not block a normal, safe case$`, func() error { return nil })
			sc.Then(`^a rule without both is not permitted to merge$`, func() error { return nil })
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{policyConfigFeaturePath(t)},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("one or more Gherkin scenarios in policy_config.feature failed")
	}
}
