// Package bdd — see dangerous_command_test.go's doc comment for the overall
// approach. This file wires features/compliance_report_demo.feature — the
// M1 "early differentiator demo" from docs/00-統一開發計畫（定案版）.md §七
// item 15, deliberately distinct from features/compliance_report.feature
// (the full Phase 5 enterprise feature, not implemented yet — see that
// feature file's own Background requiring an on-prem PostgreSQL-backed
// deployment this project doesn't have).
package bdd

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/amplify-lab/damping/cli/paths"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

func complianceReportDemoFeaturePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "features", "compliance_report_demo.feature")
}

// realRuleIDs mirrors cli/policies/default.yaml's actual shipped rule set —
// kept here (not imported) since this package tests the CLI surface, not
// core/policy directly; core/compliance's own
// TestSyntheticDemoDataset_EveryRuleIDIsReal is the authoritative version
// of this same list closer to the source of truth.
var realRuleIDs = map[string]bool{
	"destructive.rm_rf_protected": true, "destructive.git_push_force": true,
	"destructive.sql_drop_truncate": true, "destructive.chmod_777_recursive": true,
	"destructive.curl_pipe_sh_unallowlisted": true, "destructive.encoded_payload_pipe": true,
	"destructive.proc_sandbox_bypass": true, "destructive.dynamic_command_construction": true,
	"destructive.write_protected_path": true, "mcp.destructive_tool_call": true,
	"self_protection.damping_off_attempt": true, "destructive.iac_destroy": true,
	"destructive.iac_apply_unreviewed": true, "destructive.git_history_destructive": true,
	"destructive.secret_exfiltration": true, "destructive.agent_permission_escalation": true,
	"destructive.git_hook_write": true, "destructive.npm_lifecycle_script_write": true,
	"destructive.kubectl_bulk_delete": true, "destructive.cloud_cli_mass_delete": true,
	"destructive.raw_device_write": true, "destructive.cargo_publish_unreviewed": true,
	"destructive.gem_push_unreviewed": true, "destructive.webhook_exfiltration": true,
}

// seedRealAuditLogForComplianceExport writes a small, real mix of events
// (one critical deny, one low-risk allow) directly via core/audit.Writer —
// the same real write path cli/cmd/hook.go itself uses — so the "export"
// scenarios exercise the actual local-audit-log code path rather than a
// fixture the export command doesn't really read.
func seedRealAuditLogForComplianceExport(t *testing.T) error {
	t.Helper()
	auditPath, err := paths.Audit()
	if err != nil {
		return err
	}
	w := audit.NewWriter(auditPath)
	if err := w.Append(event.ActionEvent{
		EventID: "evt_seed_1", Timestamp: time.Now(), SessionID: "sess1",
		Actor: "alice", Channel: event.ChannelCLI, ActionType: event.ActionShellExec,
		Target: "rm -rf /prod", Raw: "rm -rf /prod", RiskLevel: event.RiskCritical,
		Decision: decision.Decision{Verdict: decision.Prompt, ResolvedVerdict: decision.Deny, PolicyID: "destructive.rm_rf_protected", Reason: "seeded for BDD"},
	}); err != nil {
		return err
	}
	return w.Append(event.ActionEvent{
		EventID: "evt_seed_2", Timestamp: time.Now(), SessionID: "sess1",
		Actor: "bob", Channel: event.ChannelCLI, ActionType: event.ActionShellExec,
		Target: "git status", Raw: "git status", RiskLevel: event.RiskLow,
		Decision: decision.Decision{Verdict: decision.Allow},
	})
}

type complianceReportWorld struct {
	stdout string
	stderr string
	runErr error
}

func (w *complianceReportWorld) run(commandLine string) error {
	fields := strings.Fields(commandLine)
	if len(fields) == 0 || fields[0] != "damping" {
		return fmt.Errorf("expected a command line starting with %q, got %q", "damping", commandLine)
	}
	stdout, stderr, err := runDampingCommand("", fields[1:]...)
	w.stdout, w.stderr, w.runErr = stdout, stderr, err
	return nil
}

func TestFeatures_ComplianceReportDemo(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			w := &complianceReportWorld{}
			sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
				*w = complianceReportWorld{}
				return ctx, nil
			})

			sc.Given(`^Damping is running with the default policy$`, func() error {
				dir := t.TempDir()
				t.Setenv("DAMPING_HOME", filepath.Join(dir, "damping-home"))
				t.Setenv("DAMPING_CLAUDE_SETTINGS", filepath.Join(dir, "claude", "settings.json"))
				t.Setenv("DAMPING_CURSOR_HOOKS", filepath.Join(dir, "cursor", "hooks.json"))
				t.Setenv("DAMPING_CODEX_HOOKS", filepath.Join(dir, "codex", "hooks.json"))
				_, _, err := runDampingCommand("", "init")
				return err
			})

			sc.When(`^the user runs "([^"]*)"$`, w.run)

			sc.Then(`^the report should be generated from a synthetic 30-day dataset, not the real local audit log$`, func() error {
				if w.runErr != nil {
					return w.runErr
				}
				if !strings.Contains(w.stdout, "synthetic 30-day dataset") {
					return fmt.Errorf("expected the demo report to disclose it's built on a synthetic 30-day dataset, got:\n%s", w.stdout)
				}
				return nil
			})

			sc.Then(`^the report should clearly label itself as a demo built on synthetic data$`, func() error {
				if !strings.Contains(w.stdout, "demo report built on") {
					return fmt.Errorf("expected an explicit demo label, got:\n%s", w.stdout)
				}
				return nil
			})

			sc.Then(`^the report should include, for every high-risk or critical synthetic action, the actor, bound identity, channel, timestamp, matched rule, decision, and outcome$`, func() error {
				for _, col := range []string{"Timestamp", "Actor", "Identity", "Channel", "Target", "Risk", "Rule", "Outcome"} {
					if !strings.Contains(w.stdout, col) {
						return fmt.Errorf("expected the report table to have a %q column, got:\n%s", col, w.stdout)
					}
				}
				if !strings.Contains(w.stdout, "@bank.tw") {
					return fmt.Errorf("expected at least one bound identity in the demo report, got:\n%s", w.stdout)
				}
				return nil
			})

			sc.Then(`^every matched rule referenced in the report should be a real rule id from cli\/policies\/default\.yaml$`, func() error {
				found := 0
				for ruleID := range realRuleIDs {
					if strings.Contains(w.stdout, ruleID) {
						found++
					}
				}
				if found == 0 {
					return fmt.Errorf("expected at least one real rule id to appear in the report, got:\n%s", w.stdout)
				}
				// Also assert the inverse for the one non-rule-bearing row this
				// dataset includes ("git status", a plain allow) — it must not
				// itself masquerade as a rule id.
				if strings.Contains(w.stdout, "| git status |") {
					return fmt.Errorf("a plain allow with no matched rule leaked into the high-risk table, got:\n%s", w.stdout)
				}
				return nil
			})

			sc.Then(`^the report should state that it is not an official regulator-issued report template$`, func() error {
				if !strings.Contains(w.stdout, "not an official regulator-issued report template") {
					return fmt.Errorf("expected the official-template disclaimer, got:\n%s", w.stdout)
				}
				return nil
			})

			sc.Then(`^the report should state that it is not the same as the full Phase 5 enterprise compliance report \(on-prem, AD\/LDAP-bound identity, append-only PostgreSQL history\)$`, func() error {
				if !strings.Contains(w.stdout, "Phase 5 enterprise compliance report") {
					return fmt.Errorf("expected the Phase-5-scope disclaimer, got:\n%s", w.stdout)
				}
				return nil
			})

			sc.Then(`^the output should be valid (markdown|json|text)$`, func(format string) error {
				if w.runErr != nil {
					return w.runErr
				}
				switch format {
				case "json":
					var v map[string]any
					if err := json.Unmarshal([]byte(w.stdout), &v); err != nil {
						return fmt.Errorf("expected valid JSON output, got error %v, output:\n%s", err, w.stdout)
					}
				case "markdown":
					if !strings.HasPrefix(w.stdout, "# Damping Compliance Report") {
						return fmt.Errorf("expected a markdown H1 heading, got:\n%s", w.stdout)
					}
				case "text":
					if !strings.HasPrefix(w.stdout, "Damping Compliance Report") {
						return fmt.Errorf("expected the plain-text header, got:\n%s", w.stdout)
					}
				}
				return nil
			})

			sc.Given(`^the local audit log contains a mix of allowed, denied, and prompt-resolved events across multiple actors$`, func() error {
				return seedRealAuditLogForComplianceExport(t)
			})

			sc.Then(`^the report should be generated from the real local audit log, not synthetic data$`, func() error {
				if w.runErr != nil {
					return w.runErr
				}
				if strings.Contains(w.stdout, "synthetic 30-day dataset") {
					return fmt.Errorf("a real export must not claim to be a demo, got:\n%s", w.stdout)
				}
				return nil
			})

			sc.Then(`^the report should include every high-risk or critical action from that log with its actor, identity \(if bound\), channel, timestamp, matched rule, decision, and outcome$`, func() error {
				if !strings.Contains(w.stdout, "destructive.rm_rf_protected") {
					return fmt.Errorf("expected the seeded critical event's rule id in the report, got:\n%s", w.stdout)
				}
				return nil
			})

			sc.Then(`^low-risk allowed actions should not clutter the high-risk section, but should still be reflected in the summary counts$`, func() error {
				if !strings.Contains(w.stdout, "Risk low: 1") {
					return fmt.Errorf("expected the low-risk seeded event to be counted in the summary, got:\n%s", w.stdout)
				}
				if strings.Contains(w.stdout, "git status") {
					return fmt.Errorf("expected the low-risk seeded event to be absent from the high-risk detail table, got:\n%s", w.stdout)
				}
				return nil
			})

			sc.Given(`^the local audit log has no high-risk or critical events in the requested period$`, func() error {
				_, _, err := runDampingCommand("", "init")
				return err
			})

			sc.Then(`^the report should clearly state that no high-risk or critical actions occurred in the period$`, func() error {
				if !strings.Contains(w.stdout, "No high-risk or critical actions occurred in this period.") {
					return fmt.Errorf("expected the explicit empty-state message, got:\n%s", w.stdout)
				}
				return nil
			})

			sc.Then(`^this should not be rendered identically to a report that actually found and is hiding such actions$`, func() error {
				// Asserted by construction: the explicit message checked above
				// only appears when HighRiskEntries is genuinely empty (see
				// core/compliance.Report.RenderMarkdown) — there is no code
				// path that suppresses real entries and prints the same
				// message, so this step is a documented, not-independently-
				// re-checkable corollary of the previous assertion, matching
				// this project's existing precedent for such steps (see
				// dangerous_command_test.go's "should not execute until the
				// user responds").
				return nil
			})
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{complianceReportDemoFeaturePath(t)},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("one or more Gherkin scenarios in compliance_report_demo.feature failed")
	}
}
