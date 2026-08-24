// Package bdd — see dangerous_command_test.go's doc comment for the overall
// approach. This file wires features/gui_host_integration.feature.
//
// Unlike most of this package, every scenario here drives the real
// `damping hook pretooluse` command end to end (via runDampingCommand) and
// asserts on what a host would actually receive: the process exit code, the
// JSON object on stdout, and the record left in the audit log. That is the
// whole contract under test — a host embedding Damping has nothing else to
// go on — so testing it at the policy.Evaluator level, the way the
// single-verdict scenarios elsewhere in this package do, would prove
// nothing about it.
package bdd

import (
	"context"
	"encoding/json"
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
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

func guiHostIntegrationFeaturePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "features", "gui_host_integration.feature")
}

type guiHostWorld struct {
	hookArgs   []string
	configPath string
	stdout     string
	runErr     error
}

// hookResponse is the parsed stdout body — deliberately re-declared here
// from field names rather than reusing cli/adapter/hook's own structs, so a
// rename or retagging in that package shows up as a failing scenario
// instead of being silently absorbed by the shared type. The host contract
// is the JSON on the wire, not the Go type that produced it.
type hookResponse struct {
	HookSpecificOutput *struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
	Damping struct {
		Decision string `json:"decision"`
		Verdict  string `json:"verdict"`
		PolicyID string `json:"policyId"`
		Risk     string `json:"risk"`
		Reason   string `json:"reason"`
		EventID  string `json:"eventId"`
		Degraded bool   `json:"degraded"`
		Version  string `json:"version"`
	} `json:"damping"`
}

func (w *guiHostWorld) response() (hookResponse, error) {
	var r hookResponse
	if strings.TrimSpace(w.stdout) == "" {
		return r, fmt.Errorf("expected a JSON hook response on stdout, got nothing")
	}
	if err := json.Unmarshal([]byte(w.stdout), &r); err != nil {
		return r, fmt.Errorf("parsing hook response %q: %w", w.stdout, err)
	}
	return r, nil
}

// runHook assembles the argv a host would actually exec. --config is a
// persistent root flag and the world's steps can set it in either order
// relative to the hook's own flags, so it's held separately rather than
// concatenated into hookArgs by whichever step ran first.
func (w *guiHostWorld) runHook(payload string) {
	args := []string{"hook", "pretooluse"}
	if w.configPath != "" {
		args = append(args, "--config", w.configPath)
	}
	args = append(args, w.hookArgs...)
	w.stdout, _, w.runErr = runDampingCommand(payload, args...)
}

func (w *guiHostWorld) lastAuditEvent() (event.ActionEvent, error) {
	auditPath, err := paths.Audit()
	if err != nil {
		return event.ActionEvent{}, err
	}
	events, err := audit.ReadAll(auditPath, audit.Filter{})
	if err != nil {
		return event.ActionEvent{}, err
	}
	if len(events) == 0 {
		return event.ActionEvent{}, fmt.Errorf("no audit events recorded")
	}
	return events[len(events)-1], nil
}

func bashPayload(command string) string {
	payload, err := json.Marshal(map[string]any{
		"session_id":      "bdd-host",
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]string{"command": command},
	})
	if err != nil { // impossible for this fixed shape; keeps the step honest anyway
		panic(err)
	}
	return string(payload)
}

func TestFeatures_GUIHostIntegration(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			w := &guiHostWorld{}
			sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
				*w = guiHostWorld{}
				return ctx, nil
			})

			sc.Given(`^Damping is running with the default policy$`, func() error {
				dir := t.TempDir()
				t.Setenv("DAMPING_HOME", filepath.Join(dir, "damping-home"))
				t.Setenv("DAMPING_CLAUDE_SETTINGS", filepath.Join(dir, "claude", "settings.json"))
				t.Setenv("DAMPING_CURSOR_HOOKS", filepath.Join(dir, "cursor", "hooks.json"))
				t.Setenv("DAMPING_CODEX_HOOKS", filepath.Join(dir, "codex", "hooks.json"))
				t.Setenv("DAMPING_NO_UPDATE_CHECK", "1") // init prints a passive background update-check notice; without this every scenario would make a real network call to api.github.com
				_, _, err := runDampingCommand("", "init")
				return err
			})

			sc.Given(`^the host runs the hook with "([^"]*)"$`, func(flags string) error {
				w.hookArgs = strings.Fields(flags)
				return nil
			})

			sc.Given(`^the policy resolves medium-risk prompts to allow when nobody can be asked$`, func() error {
				raw, err := os.ReadFile(defaultPolicyPath(t))
				if err != nil {
					return err
				}
				policyPath := filepath.Join(t.TempDir(), "policy.yaml")
				if err := os.WriteFile(policyPath, append(raw, []byte("\nnoninteractive_prompt_fallback:\n  medium: allow\n")...), 0o600); err != nil {
					return err
				}
				w.configPath = policyPath
				return nil
			})

			sc.When(`^the host's agent asks to run "([^"]*)"$`, func(command string) error {
				w.runHook(bashPayload(command))
				return nil
			})

			sc.When(`^the host sends a malformed hook payload$`, func() error {
				w.runHook(`{"session_id":"bdd-host",`)
				return nil
			})

			sc.Then(`^Damping should exit 0 so the host stays in control of the outcome$`, func() error {
				if w.runErr != nil {
					return fmt.Errorf("expected exit 0, got %v", w.runErr)
				}
				return nil
			})

			sc.Then(`^Damping should exit 2$`, func() error {
				var exitErr *cmd.ExitCodeError
				if !errors.As(w.runErr, &exitErr) || exitErr.Code != 2 {
					return fmt.Errorf("expected ExitCodeError{Code:2}, got %v", w.runErr)
				}
				return nil
			})

			sc.Then(`^the hook response should carry permissionDecision "([^"]*)"$`, func(want string) error {
				r, err := w.response()
				if err != nil {
					return err
				}
				if r.HookSpecificOutput == nil {
					return fmt.Errorf("expected a hookSpecificOutput block, got none: %s", w.stdout)
				}
				if r.HookSpecificOutput.PermissionDecision != want {
					return fmt.Errorf("expected permissionDecision %q, got %q", want, r.HookSpecificOutput.PermissionDecision)
				}
				if r.HookSpecificOutput.HookEventName != "PreToolUse" {
					return fmt.Errorf("expected hookEventName PreToolUse, got %q", r.HookSpecificOutput.HookEventName)
				}
				if r.HookSpecificOutput.PermissionDecisionReason == "" {
					return fmt.Errorf("expected a permissionDecisionReason the host can show a human, got none")
				}
				return nil
			})

			sc.Then(`^the hook response should carry no permissionDecision at all$`, func() error {
				r, err := w.response()
				if err != nil {
					return err
				}
				if r.HookSpecificOutput != nil {
					return fmt.Errorf("expected no hookSpecificOutput block for an allowed action, got %s", w.stdout)
				}
				return nil
			})

			sc.Then(`^the hook response should name the matched rule "([^"]*)"$`, func(want string) error {
				r, err := w.response()
				if err != nil {
					return err
				}
				if r.Damping.PolicyID != want {
					return fmt.Errorf("expected policyId %q, got %q", want, r.Damping.PolicyID)
				}
				if r.Damping.Risk == "" {
					return fmt.Errorf("expected the matched rule's risk level, got none")
				}
				return nil
			})

			sc.Then(`^the hook response should report the Damping decision "([^"]*)"$`, func(want string) error {
				r, err := w.response()
				if err != nil {
					return err
				}
				if r.Damping.Decision != want {
					return fmt.Errorf("expected damping.decision %q, got %q", want, r.Damping.Decision)
				}
				return nil
			})

			sc.Then(`^the hook response should report that Damping degraded$`, func() error {
				r, err := w.response()
				if err != nil {
					return err
				}
				if !r.Damping.Degraded {
					return fmt.Errorf("expected damping.degraded=true, got %s", w.stdout)
				}
				return nil
			})

			sc.Then(`^the audit record should show the action was deferred to the host, not resolved$`, func() error {
				ev, err := w.lastAuditEvent()
				if err != nil {
					return err
				}
				if ev.Decision.Verdict != decision.Prompt {
					return fmt.Errorf("expected a prompt verdict in the audit record, got %q", ev.Decision.Verdict)
				}
				if ev.Decision.ResolvedVerdict != "" {
					return fmt.Errorf("expected no resolved verdict — Damping never learns the host's answer — got %q", ev.Decision.ResolvedVerdict)
				}
				if !strings.Contains(ev.Decision.Reason, "deferred") {
					return fmt.Errorf("expected the audit reason to say the decision was deferred, got %q", ev.Decision.Reason)
				}
				return nil
			})

			sc.Then(`^the audit record's actor should be "([^"]*)"$`, func(want string) error {
				ev, err := w.lastAuditEvent()
				if err != nil {
					return err
				}
				if ev.Actor != want {
					return fmt.Errorf("expected actor %q, got %q", want, ev.Actor)
				}
				return nil
			})
		},
		Options: &godog.Options{
			Format: "pretty",
			Paths:  []string{guiHostIntegrationFeaturePath(t)},
			// Strict makes an undefined or pending step fail the suite. Without
			// it godog reports "undefined" and still exits 0, so a scenario
			// whose steps were never wired reads as green — which would defeat
			// the point of writing the scenario first.
			Strict:   true,
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("one or more Gherkin scenarios in gui_host_integration.feature failed")
	}
}
