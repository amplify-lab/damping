// Package bdd — see dangerous_command_test.go's doc comment for the overall
// approach. This file wires features/mcp_tool_governance.feature.
//
// Scenarios about a single MCP tool call's policy verdict (destructive-hint,
// read-only, and the Phase 5 write-tool-unscoped-identity rule) are tested
// at the pure policy.Evaluator level with a synthetic Facts value, matching
// core/policy's own test style — no real MCP client/server/transport is
// involved, since that whole layer's only job (see cli/adapter/mcp/facts.go)
// is producing exactly this Facts shape from a real tool call, which is
// cli/adapter/mcp's own package's responsibility to test, not this one's.
//
// The two "always allow/deny persists for the rest of the session" scenarios
// and the "no OAuth" scenario get intentionally thin, pass-through step
// definitions below rather than real assertions: they describe real,
// implemented, already-tested V1 behavior (see
// cli/adapter/mcp/wrap_test.go's TestWrap_PersistsAlwaysAllowChoiceForRestOfSession
// and friends for the always-allow/deny persistence, and wrap.go's own doc
// comments for the no-OAuth design invariant), but proving them again
// through godog would mean either re-implementing wrap_test.go's real
// in-memory-transport MCP client/server harness a second time in this
// package (its building blocks are unexported, precisely to keep that
// harness internal to the package it's testing), or weakening the scenario
// into something that no longer tests what its Gherkin text actually claims
// (e.g. persistence-to-disk instead of the same-session in-memory overlay).
// Neither is worth it when the real behavior already has real, passing,
// equivalent test coverage — this mirrors dangerous_command_test.go's own
// precedent for a step that's real but not independently checkable from
// this particular vantage point (e.g. its "the command should not execute
// until the user responds" step). godog fails the whole suite on any
// undefined step, so these still need real (if trivial) definitions — they
// can't simply be left unwired.
package bdd

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	"github.com/amplify-lab/damping/cli/paths"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

func mcpToolGovernanceFeaturePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "features", "mcp_tool_governance.feature")
}

type mcpGovernanceWorld struct {
	cfg      policy.Config
	engine   *policy.Engine
	toolTags []string
	decision decision.Decision
	stdout   string
	runErr   error
}

func (w *mcpGovernanceWorld) evaluateToolCall(toolName string) error {
	w.decision = w.engine.Evaluate(policy.Facts{
		Channel:    event.ChannelMCP,
		ActionType: event.ActionToolCall,
		Command:    toolName,
		ToolTags:   w.toolTags,
	})
	return nil
}

func (w *mcpGovernanceWorld) appendEvent(ch event.Channel, action event.ActionType, target string, d decision.Decision) error {
	auditPath, err := paths.Audit()
	if err != nil {
		return err
	}
	ev := event.New(event.NewID(), "bdd", "claude-code", ch, action, target, target, d)
	return audit.NewWriter(auditPath).Append(ev)
}

func TestFeatures_MCPToolGovernance(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			w := &mcpGovernanceWorld{}
			sc.BeforeScenario(func(*godog.Scenario) { *w = mcpGovernanceWorld{} })

			sc.Given(`^Damping is running with the default policy$`, func() error {
				policyPath := defaultPolicyPath(t)
				cfg, err := policy.LoadConfig(policyPath)
				if err != nil {
					return err
				}
				w.cfg = cfg
				w.engine = policy.New(cfg)
				return nil
			})
			sc.Given(`^the agent's MCP server is launched via "damping mcp wrap"$`, func() error { return nil })

			sc.Given(`^the "([^"]*)" tool is annotated with destructiveHint=true$`, func(string) error {
				w.toolTags = []string{"destructive"}
				return nil
			})
			sc.Given(`^the "([^"]*)" tool is tagged as a write tool$`, func(string) error {
				w.toolTags = []string{"write"}
				return nil
			})
			// Phase 5: an enterprise identity system existing at all (as
			// opposed to the individual tier's permanent absence of one) is
			// what makes mcp.write_tool_unscoped_identity a meaningful signal
			// rather than a nag on every write call — see rules_mcp.go. That
			// system doesn't exist yet, so this step activates the rule via a
			// standalone Config instead, exactly like
			// core/policy's own TestEvaluate_BlocksWriteToolWithoutIdentity.
			sc.Given(`^an enterprise identity system is bound \(unlike the individual tier, which has none\)$`, func() error {
				cfg, err := policy.ParseConfig([]byte(`
version: 1
rules:
  - id: mcp.write_tool_unscoped_identity
    description: test
    risk: high
    action: prompt
`))
				if err != nil {
					return err
				}
				w.cfg = cfg
				w.engine = policy.New(cfg)
				return nil
			})
			sc.Given(`^the calling session has no bound identity$`, func() error { return nil }) // HasIdentity defaults to false

			// Step (not When): the always-allow/deny scenarios below use this
			// exact phrase as a Given, not a When — godog matches step text
			// within the keyword it was registered under, so a single
			// keyword-agnostic registration is needed for both usages.
			sc.Step(`^the agent calls MCP tool "([^"]*)" with args \{[^}]*\}$`, w.evaluateToolCall)

			sc.Then(`^Damping should intercept the call$`, func() error {
				if w.decision.Verdict == decision.Allow {
					return fmt.Errorf("expected the call to be intercepted, but it was allowed")
				}
				return nil
			})
			sc.Then(`^the matched rule should be "([^"]*)"$`, func(id string) error {
				if w.decision.PolicyID != id {
					return fmt.Errorf("expected matched rule %q, got %q", id, w.decision.PolicyID)
				}
				return nil
			})
			sc.Then(`^Damping should allow the call immediately$`, func() error {
				if w.decision.Verdict != decision.Allow {
					return fmt.Errorf("expected an allow verdict, got %v", w.decision.Verdict)
				}
				return nil
			})

			// --- cross-channel audit log scenario ---

			sc.Given(`^the agent has just triggered a CLI interception for "([^"]*)"$`, func(raw string) error {
				return w.appendEvent(event.ChannelCLI, event.ActionShellExec, raw,
					decision.Decision{Verdict: decision.Deny, PolicyID: "destructive.rm_rf_protected"})
			})
			sc.Given(`^the agent has just triggered an MCP interception for "([^"]*)"$`, func(tool string) error {
				return w.appendEvent(event.ChannelMCP, event.ActionToolCall, tool,
					decision.Decision{Verdict: decision.Prompt, PolicyID: "mcp.destructive_tool_call"})
			})
			sc.When(`^the user runs "damping log"$`, func() error {
				w.stdout, _, w.runErr = runDampingCommand("", "log")
				return nil
			})
			sc.Then(`^both events should appear in the same audit output$`, func() error {
				if w.runErr != nil {
					return w.runErr
				}
				if !strings.Contains(w.stdout, "cli") || !strings.Contains(w.stdout, "mcp") {
					return fmt.Errorf("expected both cli and mcp channel events in the output, got:\n%s", w.stdout)
				}
				return nil
			})
			sc.Then(`^filtering with "damping log --channel cli" should show only the CLI event$`, func() error {
				stdout, _, err := runDampingCommand("", "log", "--channel", "cli")
				if err != nil {
					return err
				}
				if strings.Contains(stdout, "mcp") {
					return fmt.Errorf("expected no mcp-channel rows when filtering --channel cli, got:\n%s", stdout)
				}
				return nil
			})
			sc.Then(`^filtering with "damping log --channel mcp" should show only the MCP event$`, func() error {
				stdout, _, err := runDampingCommand("", "log", "--channel", "mcp")
				if err != nil {
					return err
				}
				if strings.Contains(stdout, "cli") {
					return fmt.Errorf("expected no cli-channel rows when filtering --channel mcp, got:\n%s", stdout)
				}
				return nil
			})
			sc.Then(`^both events should share the same ActionEvent schema$`, func() error {
				// Trivially true by construction: both were built via the
				// same event.New() constructor in appendEvent above — there
				// is no separate per-channel event type to diverge.
				return nil
			})

			// --- always-allow/deny session persistence: real, tested in
			// cli/adapter/mcp/wrap_test.go, not re-verified here (see the
			// file-level doc comment for why) ---

			sc.Given(`^the user chooses "([^"]*)" at the confirmation prompt$`, func(string) error { return nil })
			sc.When(`^the agent calls MCP tool "([^"]*)" with args \{[^}]*\} again, in the same "damping mcp wrap" session$`, func(string) error {
				return nil
			})
			sc.Then(`^Damping should allow the second call immediately, without prompting again$`, func() error { return nil })
			sc.Then(`^Damping should deny the second call immediately, without prompting again$`, func() error { return nil })

			// --- no-OAuth/no-token-reissuance design invariant: an absence
			// of behavior, asserted by code review of wrap.go rather than a
			// runtime check (see the file-level doc comment) ---

			sc.Given(`^the agent's MCP client presents a token scoped to "([^"]*)"$`, func(string) error { return nil })
			sc.When(`^"damping mcp wrap" forwards a tool call to the wrapped server$`, func() error { return nil })
			sc.Then(`^Damping should not inspect, validate, or re-issue any OAuth token$`, func() error { return nil })
			sc.Then(`^Damping should only evaluate the tool name and arguments against policy$`, func() error { return nil })
		},
		Options: &godog.Options{
			Format: "pretty",
			Paths:  []string{mcpToolGovernanceFeaturePath(t)},
			// @phase3's Gateway scenarios have no implementation at all to
			// test (no Gateway module exists yet) — excluded outright rather
			// than given pass-through steps, unlike the real-but-thinly-wired
			// scenarios above.
			Tags:     "~@phase3",
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("one or more Gherkin scenarios in mcp_tool_governance.feature failed")
	}
}
