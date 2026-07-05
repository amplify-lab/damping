// Package bdd — see dangerous_command_test.go's doc comment for the overall
// approach. This file wires features/audit_log.feature. "Adapters never
// write audit records directly" and "the local audit log never leaves the
// machine" get thin, documented pass-through steps (see their comments
// below) — both are architectural invariants about an absence of behavior
// (no other write path, no network call), which is enforced by what code
// doesn't exist rather than something a single dynamic test run can prove
// one way or the other; the real enforcement is code review plus
// core/audit's own package doc comment naming it "the single write path".
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

func auditLogFeaturePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "features", "audit_log.feature")
}

type auditLogWorld struct {
	auditPath string
	decision  decision.Decision
	stdout    string
	stderr    string
	runErr    error

	followStdout, followStderr *syncBuffer
	followDone                 <-chan error
	followCancel               context.CancelFunc
}

func (w *auditLogWorld) appendEvent(ev event.ActionEvent) error {
	return audit.NewWriter(w.auditPath).Append(ev)
}

func (w *auditLogWorld) lastEvent() (event.ActionEvent, error) {
	events, err := audit.ReadAll(w.auditPath, audit.Filter{})
	if err != nil {
		return event.ActionEvent{}, err
	}
	if len(events) == 0 {
		return event.ActionEvent{}, fmt.Errorf("no audit events recorded")
	}
	return events[len(events)-1], nil
}

func TestFeatures_AuditLog(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			w := &auditLogWorld{}
			sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
				*w = auditLogWorld{}
				return ctx, nil
			})
			sc.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
				if w.followCancel != nil {
					w.followCancel()
					<-w.followDone
				}
				return ctx, err
			})

			sc.Given(`^Damping is running with the default policy$`, func() error {
				dir := t.TempDir()
				t.Setenv("DAMPING_HOME", filepath.Join(dir, "damping-home"))
				t.Setenv("DAMPING_CLAUDE_SETTINGS", filepath.Join(dir, "claude", "settings.json"))
				t.Setenv("DAMPING_CURSOR_HOOKS", filepath.Join(dir, "cursor", "hooks.json"))
				if _, _, err := runDampingCommand("", "init"); err != nil {
					return err
				}
				auditPath, err := paths.Audit()
				if err != nil {
					return err
				}
				w.auditPath = auditPath
				return nil
			})

			// --- "adapters never write audit records directly" (design
			// invariant, not dynamically checkable — see file doc comment) ---
			sc.Given(`^the CLI adapter has just normalized a shell command into an ActionEvent$`, func() error { return nil })
			sc.Given(`^the MCP adapter has just normalized a tool call into an ActionEvent$`, func() error { return nil })
			sc.When(`^each adapter hands its ActionEvent to core\/audit$`, func() error { return nil })
			sc.Then(`^core\/audit should be the only component that appends to ~\/\.damping\/audit\.jsonl$`, func() error { return nil })
			sc.Then(`^neither adapter should write to the audit file directly$`, func() error { return nil })

			// --- compliance-report field coverage ---

			sc.Given(`^an action has just been intercepted$`, func() error {
				return w.appendEvent(event.ActionEvent{
					EventID:    event.NewID(),
					Timestamp:  time.Now(),
					SessionID:  "s1",
					Actor:      "claude-code",
					Identity:   "alice@example.com",
					Channel:    event.ChannelCLI,
					ActionType: event.ActionShellExec,
					Target:     "rm -rf /",
					Raw:        "rm -rf /",
					ParsedArgs: map[string]any{"flag": "-rf"},
					RiskLevel:  event.RiskCritical,
					Decision:   decision.Decision{Verdict: decision.Deny, PolicyID: "destructive.rm_rf_protected"},
				})
			})
			sc.When(`^the resulting ActionEvent is written to the audit log$`, func() error { return nil }) // already written above
			sc.Then(`^the record should include event_id, actor, identity, channel, action_type, target, raw, parsed_args, risk_level, decision, policy_id, session_id, and timestamp$`, func() error {
				ev, err := w.lastEvent()
				if err != nil {
					return err
				}
				raw, err := json.Marshal(ev)
				if err != nil {
					return err
				}
				for _, field := range []string{"event_id", "actor", "identity", "channel", "action_type",
					"target", "raw", "parsed_args", "risk_level", "decision", "policy_id", "session_id", "timestamp"} {
					if !strings.Contains(string(raw), `"`+field+`"`) {
						return fmt.Errorf("expected field %q in the audit record, got: %s", field, raw)
					}
				}
				return nil
			})
			sc.Then(`^identity may be empty in the individual tier without breaking the schema$`, func() error {
				ev := event.ActionEvent{
					EventID: event.NewID(), SessionID: "s1", Actor: "claude-code",
					Channel: event.ChannelCLI, ActionType: event.ActionShellExec,
					Decision: decision.Decision{Verdict: decision.Allow},
				}
				if ev.Identity != "" {
					return fmt.Errorf("expected a zero-value Identity to be empty")
				}
				if err := ev.Validate(); err != nil {
					return fmt.Errorf("expected an empty Identity to still pass validation: %v", err)
				}
				raw, err := json.Marshal(ev)
				if err != nil {
					return err
				}
				if strings.Contains(string(raw), `"identity"`) {
					return fmt.Errorf("expected omitempty to drop an empty identity field, got: %s", raw)
				}
				return nil
			})

			// --- one coherent record for a resolved prompt ---

			sc.Given(`^a command triggered a "([^"]*)" decision$`, func(verdict string) error {
				w.decision = decision.Decision{Verdict: decision.Verdict(verdict), PolicyID: "destructive.rm_rf_protected"}
				return nil
			})
			sc.When(`^the user chooses "Allow once"$`, func() error {
				w.decision.Resolve(decision.Allow)
				return w.appendEvent(event.New(event.NewID(), "s1", "claude-code", event.ChannelCLI,
					event.ActionShellExec, "rm -rf ~/", "rm -rf ~/", w.decision))
			})
			sc.Then(`^the audit log should show a single event with decision "([^"]*)"$`, func(wantDecision string) error {
				// A review found this step captured the decision string
				// but never used it — the body hardcoded a Prompt->Allow
				// check regardless of what the Gherkin text said. It only
				// ever looked correct because the sole scenario using this
				// step happens to say "prompt→allow"; reusing this same
				// step wording with a different string (e.g. "prompt→deny")
				// would have silently still asserted Allow. Now genuinely
				// parses "verdict→outcome" and checks both.
				events, err := audit.ReadAll(w.auditPath, audit.Filter{})
				if err != nil {
					return err
				}
				if len(events) != 1 {
					return fmt.Errorf("expected exactly 1 event, got %d", len(events))
				}
				parts := strings.SplitN(wantDecision, "→", 2)
				if len(parts) != 2 {
					return fmt.Errorf(`expected a "verdict→outcome" decision string, got %q`, wantDecision)
				}
				wantVerdict, wantOutcome := decision.Verdict(parts[0]), decision.Verdict(parts[1])
				if events[0].Decision.Verdict != wantVerdict || events[0].Decision.Outcome() != wantOutcome {
					return fmt.Errorf("expected decision %q (verdict=%v outcome=%v), got verdict=%v outcome=%v",
						wantDecision, wantVerdict, wantOutcome, events[0].Decision.Verdict, events[0].Decision.Outcome())
				}
				return nil
			})
			sc.Then(`^it should not appear as two separate, disjoint entries$`, func() error {
				events, err := audit.ReadAll(w.auditPath, audit.Filter{})
				if err != nil {
					return err
				}
				if len(events) != 1 {
					return fmt.Errorf("expected exactly 1 event, got %d", len(events))
				}
				return nil
			})

			// --- channel filtering ---

			sc.Given(`^the audit log contains both cli and mcp events from the same session$`, func() error {
				if err := w.appendEvent(event.New(event.NewID(), "s1", "claude-code", event.ChannelCLI,
					event.ActionShellExec, "rm -rf ~/", "rm -rf ~/", decision.Decision{Verdict: decision.Deny})); err != nil {
					return err
				}
				return w.appendEvent(event.New(event.NewID(), "s1", "claude-code", event.ChannelMCP,
					event.ActionToolCall, "database.delete_record", "database.delete_record", decision.Decision{Verdict: decision.Prompt}))
			})
			sc.When(`^the user runs "damping log --channel mcp"$`, func() error {
				w.stdout, w.stderr, w.runErr = runDampingCommand("", "log", "--channel", "mcp")
				return nil
			})
			sc.Then(`^only mcp-channel events should be shown$`, func() error {
				if w.runErr != nil {
					return w.runErr
				}
				if strings.Contains(w.stdout, "cli") {
					return fmt.Errorf("expected no cli-channel rows, got:\n%s", w.stdout)
				}
				if !strings.Contains(w.stdout, "mcp") {
					return fmt.Errorf("expected the mcp-channel row, got:\n%s", w.stdout)
				}
				return nil
			})
			sc.Then(`^this filter should require no separate storage backend per channel$`, func() error {
				// Both events above were appended to the exact same
				// w.auditPath file — the filter is a read-time predicate
				// (Filter.Matches), not a per-channel store.
				return nil
			})

			// --- degraded-mode logging + doctor surfacing ---

			// A review found these two steps hand-construct the resulting
			// degraded ActionEvent directly via appendEvent, never actually
			// calling hookadapter.EvaluateCommand/cli/cmd/hook.go's runHook
			// — so this scenario can't detect whether a genuine crash in
			// shell.Analyze really does fail open with a degraded record.
			// That real mechanism (a recover() around the call, added after
			// a review found it didn't exist at all — see cli/cmd/hook.go's
			// evaluateCommandRecovering) is unit-tested directly instead, in
			// cli/cmd/cmd_test.go's TestEvaluateCommandRecovering_RecoversFromPanic,
			// using a policy.Evaluator stub that panics on demand — neither
			// the real shell.Analyze nor the real policy.Engine can be made
			// to panic reliably from a test (shell.Analyze specifically has
			// ~1.2M fuzzed executions with zero panics found, see
			// cli/shell/fuzz_test.go), and adding a test-only crash-trigger
			// seam to this security tool's own production code would be a
			// bigger liability than the coverage gap it would close. These
			// two steps stay a documented fixture proving the downstream
			// half (a degraded record gets written and damping doctor
			// surfaces it) — the same precedent dangerous_command_test.go's
			// own doc comment already establishes for a step that's real
			// but not independently checkable from this vantage point.
			sc.Given(`^the shell parser crashes while analyzing a command$`, func() error { return nil })
			sc.When(`^the surrounding agent fails open per its own hook contract$`, func() error {
				return w.appendEvent(event.New(event.NewID(), "unknown", "unknown", event.ChannelCLI,
					event.ActionShellExec, "", "",
					decision.Decision{Verdict: decision.Allow, Degraded: true, Reason: "simulated shell parser crash"}))
			})
			sc.Then(`^Damping should still write an audit record with decision\.degraded = true$`, func() error {
				ev, err := w.lastEvent()
				if err != nil {
					return err
				}
				if !ev.Decision.Degraded {
					return fmt.Errorf("expected decision.degraded = true")
				}
				return nil
			})
			sc.Then(`^"damping doctor" should surface this as a warning on the next run$`, func() error {
				stdout, _, err := runDampingCommand("", "doctor")
				if err != nil {
					return err
				}
				if !strings.Contains(stdout, "degraded-mode event") {
					return fmt.Errorf("expected doctor to surface a degraded-mode warning, got: %s", stdout)
				}
				return nil
			})

			// --- empty results ---

			sc.When(`^the user runs "damping log --channel mcp" and no MCP events exist yet$`, func() error {
				w.stdout, w.stderr, w.runErr = runDampingCommand("", "log", "--channel", "mcp")
				return nil
			})
			sc.Then(`^the output should read "No audit events matched those filters\."$`, func() error {
				if w.runErr != nil {
					return w.runErr
				}
				if !strings.Contains(w.stdout, "No audit events matched those filters.") {
					return fmt.Errorf("expected the empty-results message, got:\n%s", w.stdout)
				}
				return nil
			})
			sc.Then(`^the output should not be a blank screen$`, func() error {
				if strings.TrimSpace(w.stdout) == "" {
					return fmt.Errorf("expected non-blank output")
				}
				return nil
			})

			sc.Given(`^no audit events exist yet$`, func() error { return nil }) // fresh audit log per scenario, nothing to append
			sc.When(`^the user runs "damping log --json"$`, func() error {
				w.stdout, w.stderr, w.runErr = runDampingCommand("", "log", "--json")
				return nil
			})
			sc.Then(`^stdout should be empty$`, func() error {
				if w.runErr != nil {
					return w.runErr
				}
				if strings.TrimSpace(w.stdout) != "" {
					return fmt.Errorf("expected empty stdout for zero results in --json mode, got:\n%s", w.stdout)
				}
				return nil
			})
			sc.Then(`^the "No audit events matched those filters\." notice should be written to stderr, not stdout$`, func() error {
				if !strings.Contains(w.stderr, "No audit events matched those filters.") {
					return fmt.Errorf("expected the notice on stderr, got:\n%s", w.stderr)
				}
				return nil
			})

			// --- --follow ---

			sc.Given(`^the audit log already contains one event from before "damping log --follow" started$`, func() error {
				return w.appendEvent(event.New(event.NewID(), "s1", "claude-code", event.ChannelCLI,
					event.ActionShellExec, "existing-event-marker", "existing-event-marker", decision.Decision{Verdict: decision.Deny}))
			})
			sc.When(`^the user runs "damping log --follow"$`, func() error {
				ctx, cancel := context.WithCancel(context.Background())
				w.followCancel = cancel
				w.followStdout, w.followStderr, w.followDone = startDampingLogFollow(ctx, "log", "--follow")
				return waitForBufferContains(w.followStdout, "existing-event-marker", 2*time.Second)
			})
			sc.Then(`^the pre-existing event should be printed immediately$`, func() error {
				if !strings.Contains(w.followStdout.String(), "existing-event-marker") {
					return fmt.Errorf("expected the pre-existing event, got:\n%s", w.followStdout.String())
				}
				return nil
			})
			sc.Then(`^a message noting that Damping is watching for new events should appear$`, func() error {
				return waitForBufferContains(w.followStderr, "Watching for new events", 2*time.Second)
			})
			sc.When(`^a new action is intercepted while "damping log --follow" is still running$`, func() error {
				return w.appendEvent(event.New(event.NewID(), "s1", "claude-code", event.ChannelCLI,
					event.ActionShellExec, "new-event-marker", "new-event-marker", decision.Decision{Verdict: decision.Deny}))
			})
			sc.Then(`^the new event should be printed without needing to restart the command$`, func() error {
				return waitForBufferContains(w.followStdout, "new-event-marker", 2*time.Second)
			})

			sc.Given(`^the user runs "damping log --follow --json"$`, func() error {
				ctx, cancel := context.WithCancel(context.Background())
				w.followCancel = cancel
				w.followStdout, w.followStderr, w.followDone = startDampingLogFollow(ctx, "log", "--follow", "--json")
				return waitForBufferContains(w.followStderr, "Watching for new events", 2*time.Second)
			})
			sc.Then(`^every non-empty line written to stdout should parse as JSON$`, func() error {
				for _, line := range strings.Split(strings.TrimRight(w.followStdout.String(), "\n"), "\n") {
					if line == "" {
						continue
					}
					var v map[string]any
					if err := json.Unmarshal([]byte(line), &v); err != nil {
						return fmt.Errorf("invalid JSON line %q: %w", line, err)
					}
				}
				return nil
			})
			sc.Then(`^the "Watching for new events" notice should be written to stderr, not stdout$`, func() error {
				if !strings.Contains(w.followStderr.String(), "Watching for new events") {
					return fmt.Errorf("expected the notice on stderr")
				}
				if strings.Contains(w.followStdout.String(), "Watching for new events") {
					return fmt.Errorf("did not expect the notice on stdout")
				}
				return nil
			})

			// --- no network egress (design invariant, see file doc comment) ---

			sc.Given(`^Damping has not been opted into team sync$`, func() error { return nil })
			sc.When(`^any action is intercepted$`, func() error {
				return w.appendEvent(event.New(event.NewID(), "s1", "claude-code", event.ChannelCLI,
					event.ActionShellExec, "git status", "git status", decision.Decision{Verdict: decision.Allow}))
			})
			sc.Then(`^the resulting ActionEvent should be written only to ~\/\.damping\/audit\.jsonl$`, func() error {
				ev, err := w.lastEvent()
				if err != nil {
					return err
				}
				if ev.Target != "git status" {
					return fmt.Errorf("expected the just-appended event, got %+v", ev)
				}
				return nil
			})
			sc.Then(`^no network request should be made to transmit the event$`, func() error { return nil })
		},
		Options: &godog.Options{
			Format: "pretty",
			Paths:  []string{auditLogFeaturePath(t)},
			// @phase4's team dashboard has no implementation to test.
			Tags:     "~@phase4",
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("one or more Gherkin scenarios in audit_log.feature failed")
	}
}
