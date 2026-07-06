// Package bdd — see dangerous_command_test.go's doc comment for the overall
// approach. This file wires features/agent_config_write.feature.
//
// Like mcp_tool_governance_test.go, these scenarios are tested at the pure
// policy.Evaluator level with Facts built via
// cli/adapter/hook.FactsFromToolWrite — the same function cli/cmd/hook.go's
// real runHook calls for a Write/Edit/MultiEdit tool call. The real
// stdin-to-exit-code wiring (hook_event_name discrimination, actor
// attribution, audit Target/Raw split) is proven separately in
// cli/cmd/cmd_test.go's TestHook_* Write/Edit/MultiEdit tests — this file's
// job is the policy-matching behavior itself, not re-proving the plumbing.
package bdd

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cucumber/godog"

	hookadapter "github.com/amplify-lab/damping/cli/adapter/hook"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/policy"
)

func agentConfigWriteFeaturePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "features", "agent_config_write.feature")
}

type configWriteWorld struct {
	cfg      policy.Config
	engine   *policy.Engine
	decision decision.Decision
}

func TestFeatures_AgentConfigWrite(t *testing.T) {
	policyPath := defaultPolicyPath(t)

	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			w := &configWriteWorld{}
			sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
				*w = configWriteWorld{}
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

			sc.When(`^the agent writes "([^"]*)" with content:$`, func(path string, content *godog.DocString) error {
				f := hookadapter.FactsFromToolWrite("Write", hookadapter.ToolWriteInput{
					FilePath: path,
					Content:  content.Content,
				})
				w.decision = w.engine.Evaluate(f)
				return nil
			})

			sc.When(`^the agent edits "([^"]*)" so its new content includes:$`, func(path string, content *godog.DocString) error {
				f := hookadapter.FactsFromToolWrite("Edit", hookadapter.ToolWriteInput{
					FilePath: path,
					Edits:    []hookadapter.ToolEditOp{{NewString: content.Content}},
				})
				w.decision = w.engine.Evaluate(f)
				return nil
			})

			sc.When(`^the agent multi-edits "([^"]*)" so its new content includes:$`, func(path string, content *godog.DocString) error {
				f := hookadapter.FactsFromToolWrite("MultiEdit", hookadapter.ToolWriteInput{
					FilePath: path,
					Edits:    []hookadapter.ToolEditOp{{NewString: content.Content}},
				})
				w.decision = w.engine.Evaluate(f)
				return nil
			})

			sc.Then(`^Damping should intercept the write$`, func() error {
				if w.decision.Verdict == decision.Allow {
					return fmt.Errorf("expected the write to be intercepted, but it was allowed")
				}
				return nil
			})
			sc.Then(`^the matched rule should be "([^"]*)"$`, func(id string) error {
				if w.decision.PolicyID != id {
					return fmt.Errorf("expected matched rule %q, got %q", id, w.decision.PolicyID)
				}
				return nil
			})
			sc.Then(`^Damping should allow the write immediately$`, func() error {
				if w.decision.Verdict != decision.Allow {
					return fmt.Errorf("expected allow, got verdict %v (rule %q)", w.decision.Verdict, w.decision.PolicyID)
				}
				return nil
			})

			// --- Claude-Code-only scope disclosure: a design invariant, not
			// a runtime check — see the feature scenario's own comment. ---
			sc.Given(`^a Write/Edit/MultiEdit tool call can only ever originate from Claude Code's own hook contract$`, func() error { return nil })
			sc.Then(`^Cursor's afterFileEdit hook cannot block the write before it happens, only observe it after$`, func() error { return nil })
			sc.Then(`^Codex's PreToolUse hook never fires for a Write/Edit/MultiEdit tool call at all$`, func() error { return nil })
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{agentConfigWriteFeaturePath(t)},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("one or more Gherkin scenarios in agent_config_write.feature failed")
	}
}
