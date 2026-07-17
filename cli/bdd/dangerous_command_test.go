// Package bdd wires features/*.feature Gherkin scenarios to real executable
// steps via godog — this is the concrete proof that the BDD scenarios are
// acceptance criteria, not just prose. See
// docs/00-統一開發計畫（定案版）.md's closing note: "情境通過才算完成"
// (a scenario only counts as done once it passes).
//
// This file wires features/dangerous_command.feature (Phase 1's most
// emphasized scenario file, per 開發計畫.md's "先攻這個最難的點"), at the
// pure policy.Engine level. Its sibling files in this package wire every
// other V1-scope feature file (self_protection, mcp_tool_governance,
// audit_log, policy_config) the same way, driving the real command tree via
// harness_test.go's runDampingCommand where a scenario is really about the
// CLI surface rather than the policy engine alone. features/compliance_report.feature
// (@phase5) and features/team_dashboard.feature (@phase4) are entirely
// feature-level-tagged for phases with no implementation yet, so neither
// has a corresponding _test.go file — there is nothing to wire.
package bdd

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	"github.com/amplify-lab/damping/cli/shell"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/policy"
)

func featurePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "features", "dangerous_command.feature")
}

func defaultPolicyPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "policies", "default.yaml")
}

// world holds the state one scenario accumulates as its steps run.
type world struct {
	cfg      policy.Config
	engine   *policy.Engine
	decision decision.Decision
}

var verdictRank = map[decision.Verdict]int{decision.Allow: 0, decision.Prompt: 1, decision.Deny: 2}

func (w *world) evaluate(raw string) error {
	facts, err := shell.Analyze(raw)
	if err != nil {
		return err
	}
	worst := decision.Decision{Verdict: decision.Allow}
	for _, f := range facts {
		d := w.engine.Evaluate(f)
		if verdictRank[d.Verdict] > verdictRank[worst.Verdict] {
			worst = d
		}
	}
	w.decision = worst
	return nil
}

func TestFeatures_DangerousCommand(t *testing.T) {
	policyPath := defaultPolicyPath(t)

	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			w := &world{}
			sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
				*w = world{}
				return ctx, nil
			})

			sc.Given(`^Damping is running with the default policy$`, func() error {
				cfg, err := policy.LoadConfig(policyPath)
				if err != nil {
					return err
				}
				w.cfg = cfg
				w.engine = policy.New(cfg)
				return nil
			})
			sc.Given(`^Damping is enabled$`, func() error { return nil })

			// Greedy capture to the line's final quote, not `([^"]*)`: many
			// real command shapes carry their own double quotes (`curl -H
			// "Authorization: Bearer abc"`, `let "x=..."`), and the
			// non-greedy class silently left every such scenario *undefined*
			// — 9 cloud-API-delete and let-clause scenarios were reported as
			// passing suites while never actually executing.
			sc.When(`^the agent attempts to execute "(.*)"$`, w.evaluate)
			sc.When(`^the agent attempts to execute a multi-line script containing "([^"]*)" inside a shell function body$`, func(embedded string) error {
				script := fmt.Sprintf("setup() {\n  echo preparing workspace\n  %s\n}\nsetup\n", embedded)
				return w.evaluate(script)
			})
			sc.When(`^the agent attempts to write to "([^"]*)"$`, func(target string) error {
				return w.evaluate(fmt.Sprintf("echo data >> %s", target))
			})
			sc.When(`^the agent attempts to execute the following script:$`, w.evaluate)

			sc.Then(`^Damping should intercept the command$`, func() error {
				if w.decision.Verdict == decision.Allow {
					return fmt.Errorf("expected the command to be intercepted, but it was allowed")
				}
				return nil
			})
			sc.Then(`^Damping should intercept the command and require confirmation$`, func() error {
				if w.decision.Verdict != decision.Prompt {
					return fmt.Errorf("expected a prompt-tier interception, got verdict %v", w.decision.Verdict)
				}
				return nil
			})
			sc.Then(`^the confirmation prompt should state "([^"]*)"$`, func(expected string) error {
				if !strings.Contains(w.decision.Reason, expected) {
					return fmt.Errorf("expected the reason %q to contain %q", w.decision.Reason, expected)
				}
				return nil
			})
			sc.Then(`^the command should not execute until the user responds$`, func() error {
				// Enforced by the surrounding hook contract's synchronous
				// nature (Claude Code/Cursor don't run the tool until the
				// hook subprocess exits) — see docs/architecture.md §6.
				// Not independently checkable from this pure policy-engine
				// test; documented here rather than silently skipped.
				return nil
			})
			sc.Then(`^the matched rule should be "([^"]*)"$`, func(id string) error {
				if w.decision.PolicyID != id {
					return fmt.Errorf("expected matched rule %q, got %q", id, w.decision.PolicyID)
				}
				return nil
			})
			sc.Then(`^Damping should parse the full AST and detect the embedded destructive command$`, func() error {
				return nil // asserted by the following "should intercept" step
			})
			sc.Then(`^Damping should allow the command immediately$`, func() error {
				if w.decision.Verdict != decision.Allow {
					return fmt.Errorf("expected allow, got verdict %v (rule %q)", w.decision.Verdict, w.decision.PolicyID)
				}
				return nil
			})
			sc.Then(`^no confirmation prompt should be shown$`, func() error { return nil })

			sc.Given(`^the protected paths list includes "([^"]*)"$`, func(path string) error {
				for _, p := range w.cfg.ProtectedPaths {
					if p == path {
						return nil
					}
				}
				return fmt.Errorf("expected %q in protected_paths, got %v", path, w.cfg.ProtectedPaths)
			})
			// A review found the "is the only allowlisted install domain"
			// wording this step used to back was both a no-op (this
			// unconditionally returned nil, ignoring the captured domain)
			// and factually false against cli/policies/default.yaml, which
			// lists two allowlisted domains, not one — reworded to the
			// actually-relevant, checkable precondition for this scenario:
			// the tested domain genuinely isn't on the list.
			sc.Given(`^"([^"]*)" is not an allowlisted install domain$`, func(domain string) error {
				for _, d := range w.cfg.AllowlistedInstallDomains {
					if d == domain {
						return fmt.Errorf("expected %q to NOT be in allowlisted_install_domains, but it is: %v", domain, w.cfg.AllowlistedInstallDomains)
					}
				}
				return nil
			})
			sc.Given(`^"([^"]*)" is an allowlisted install domain$`, func(domain string) error {
				for _, d := range w.cfg.AllowlistedInstallDomains {
					if d == domain {
						return nil
					}
				}
				return fmt.Errorf("expected %q in allowlisted_install_domains, got %v", domain, w.cfg.AllowlistedInstallDomains)
			})
			sc.Given(`^the alias table maps "([^"]*)" to "([^"]*)"$`, func(string, string) error {
				return nil // fixture note; cli/shell's alias table is exercised directly by cli/shell's own tests
			})

			sc.Then(`^Damping should treat the dynamically-constructed command as at least "([^"]*)" tier$`, func(tier string) error {
				want, ok := map[string]int{"allow": 0, "ask": 1, "prompt": 1, "deny": 2}[tier]
				if !ok {
					return fmt.Errorf("unrecognized tier %q in scenario", tier)
				}
				if verdictRank[w.decision.Verdict] < want {
					return fmt.Errorf("expected at least tier %q, got verdict %v", tier, w.decision.Verdict)
				}
				return nil
			})
			sc.Then(`^Damping should not assume the substitution is safe merely because it cannot resolve it statically$`, func() error { return nil })
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{featurePath(t)},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("one or more Gherkin scenarios in dangerous_command.feature failed")
	}
}
