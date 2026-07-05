// This file wires features/local_dashboard.feature — the local, single-
// machine audit-log viewer (cli/dashboard, `damping dashboard`). Unlike its
// sibling _test.go files, most of these steps talk to a real
// httptest.Server wrapping dashboard.Server's actual http.Handler, not the
// cobra command tree — the command itself is a two-line wrapper
// (cli/cmd/dashboard.go) around net/http.ListenAndServe, so there is
// nothing meaningfully different to exercise there beyond its default flag
// values, which the localhost-only scenario checks directly against
// cmd.NewRootCmd() instead.
package bdd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/amplify-lab/damping/cli/cmd"
	"github.com/amplify-lab/damping/cli/dashboard"
	"github.com/amplify-lab/damping/cli/policies"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

func localDashboardFeaturePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "features", "local_dashboard.feature")
}

type localDashboardWorld struct {
	auditPath  string
	policyPath string
	httpServer *httptest.Server

	respStatus int
	respBody   string

	streamResp   *http.Response
	streamCancel context.CancelFunc
}

func (w *localDashboardWorld) appendEvent(ev event.ActionEvent) error {
	return audit.NewWriter(w.auditPath).Append(ev)
}

func (w *localDashboardWorld) get(path string) error {
	resp, err := http.Get(w.httpServer.URL + path) // #nosec G107 -- path is a fixed literal from this test's own step defs, never external input
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	w.respStatus = resp.StatusCode
	w.respBody = string(body)
	return nil
}

func TestFeatures_LocalDashboard(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			w := &localDashboardWorld{}
			sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
				dir := t.TempDir()
				*w = localDashboardWorld{
					auditPath:  filepath.Join(dir, "audit.jsonl"),
					policyPath: filepath.Join(dir, "policy.yaml"),
				}
				if err := os.WriteFile(w.policyPath, []byte(policies.Default), 0o600); err != nil {
					return ctx, err
				}
				srv := dashboard.NewServer(dashboard.Config{AuditPath: w.auditPath, PolicyPath: w.policyPath})
				w.httpServer = httptest.NewServer(srv.Handler())
				return ctx, nil
			})
			sc.After(func(ctx context.Context, _ *godog.Scenario, err error) (context.Context, error) {
				if w.streamCancel != nil {
					w.streamCancel()
				}
				if w.streamResp != nil {
					_ = w.streamResp.Body.Close()
				}
				w.httpServer.Close()
				return ctx, err
			})

			sc.Given(`^Damping is running with the default policy$`, func() error { return nil })
			sc.Given(`^Damping enforcement is on with a valid policy loaded$`, func() error { return nil })
			sc.Given(`^the policy file cannot be loaded$`, func() error {
				return os.Remove(w.policyPath)
			})
			sc.Given(`^the audit log contains both cli and mcp events from the same session$`, func() error {
				if err := w.appendEvent(event.New(event.NewID(), "s1", "claude-code", event.ChannelCLI,
					event.ActionShellExec, "rm", "rm -rf ~/", decision.Decision{Verdict: decision.Deny})); err != nil {
					return err
				}
				return w.appendEvent(event.New(event.NewID(), "s1", "claude-code", event.ChannelMCP,
					event.ActionToolCall, "database.delete_record", "database.delete_record", decision.Decision{Verdict: decision.Prompt}))
			})
			sc.Given(`^the audit log contains events at every risk level$`, func() error {
				for _, risk := range []event.RiskLevel{event.RiskLow, event.RiskMedium, event.RiskHigh, event.RiskCritical} {
					ev := event.New(event.NewID(), "s1", "claude-code", event.ChannelCLI, event.ActionShellExec, "x", "x",
						decision.Decision{Verdict: decision.Allow})
					ev.RiskLevel = risk // event.New derives risk from verdict alone; this scenario needs every level regardless of verdict
					if err := w.appendEvent(ev); err != nil {
						return err
					}
				}
				return nil
			})
			sc.Given(`^no audit events exist yet$`, func() error { return nil })
			sc.Given(`^a browser has an open connection to the dashboard's live event stream$`, func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				w.streamCancel = cancel
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.httpServer.URL+"/api/events/stream", nil)
				if err != nil {
					return err
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return err
				}
				w.streamResp = resp
				return nil
			})
			sc.Given(`^the user starts the dashboard with its default settings$`, func() error { return nil })

			sc.When(`^a browser requests the dashboard's summary$`, func() error { return w.get("/api/summary") })
			sc.When(`^a browser requests the dashboard's event stream$`, func() error { return w.get("/api/events") })
			sc.When(`^a browser requests the event stream filtered to risk "([^"]*)"$`, func(risk string) error {
				return w.get("/api/events?risk=" + risk)
			})
			sc.When(`^a new action is intercepted$`, func() error {
				time.Sleep(50 * time.Millisecond) // give the stream's poll loop time to start before we append — see core/audit.Follow's own tests for the same pattern
				return w.appendEvent(event.New(event.NewID(), "s1", "claude-code", event.ChannelCLI,
					event.ActionShellExec, "rm", "rm -rf ~/", decision.Decision{Verdict: decision.Deny}))
			})

			sc.Then(`^the summary should report enforcement enabled$`, func() error {
				var s struct {
					Enabled bool `json:"enabled"`
				}
				if err := json.Unmarshal([]byte(w.respBody), &s); err != nil {
					return err
				}
				if !s.Enabled {
					return fmt.Errorf("expected enabled=true, got: %s", w.respBody)
				}
				return nil
			})
			sc.Then(`^the summary should report the policy's rule count$`, func() error {
				var s struct {
					RuleCount int `json:"rule_count"`
				}
				if err := json.Unmarshal([]byte(w.respBody), &s); err != nil {
					return err
				}
				if s.RuleCount == 0 {
					return fmt.Errorf("expected a non-zero rule count, got: %s", w.respBody)
				}
				return nil
			})
			sc.Then(`^the summary should report which agents are registered$`, func() error {
				if !strings.Contains(w.respBody, `"agents"`) {
					return fmt.Errorf("expected an agents field, got: %s", w.respBody)
				}
				return nil
			})
			sc.Then(`^the summary should report a policy error$`, func() error {
				var s struct {
					PolicyError string `json:"policy_error"`
				}
				if err := json.Unmarshal([]byte(w.respBody), &s); err != nil {
					return err
				}
				if s.PolicyError == "" {
					return fmt.Errorf("expected a non-empty policy_error, got: %s", w.respBody)
				}
				return nil
			})
			sc.Then(`^events from both channels should be included in the response$`, func() error {
				var events []event.ActionEvent
				if err := json.Unmarshal([]byte(w.respBody), &events); err != nil {
					return err
				}
				var sawCLI, sawMCP bool
				for _, e := range events {
					sawCLI = sawCLI || e.Channel == event.ChannelCLI
					sawMCP = sawMCP || e.Channel == event.ChannelMCP
				}
				if !sawCLI || !sawMCP {
					return fmt.Errorf("expected both channels represented, got: %s", w.respBody)
				}
				return nil
			})
			sc.Then(`^only critical-risk events should be included in the response$`, func() error {
				var events []event.ActionEvent
				if err := json.Unmarshal([]byte(w.respBody), &events); err != nil {
					return err
				}
				if len(events) == 0 {
					return fmt.Errorf("expected at least one critical-risk event, got none")
				}
				for _, e := range events {
					if e.RiskLevel != event.RiskCritical {
						return fmt.Errorf("expected only critical-risk events, got a %s event", e.RiskLevel)
					}
				}
				return nil
			})
			sc.Then(`^the response should be an empty list, not an error$`, func() error {
				if w.respStatus != http.StatusOK {
					return fmt.Errorf("expected 200, got %d", w.respStatus)
				}
				if strings.TrimSpace(w.respBody) != "[]" {
					return fmt.Errorf("expected a literal empty JSON array, got: %s", w.respBody)
				}
				return nil
			})
			sc.Then(`^the new event should be pushed to the open connection without the browser needing to reconnect$`, func() error {
				scanner := bufio.NewScanner(w.streamResp.Body)
				for scanner.Scan() {
					if strings.HasPrefix(scanner.Text(), "data: ") {
						return nil
					}
				}
				if err := scanner.Err(); err != nil {
					return err
				}
				return fmt.Errorf("stream closed before pushing the new event")
			})
			sc.Then(`^it should bind only to 127\.0\.0\.1$`, func() error {
				dashboardCmd, _, err := cmd.NewRootCmd().Find([]string{"dashboard"})
				if err != nil {
					return err
				}
				hostFlag := dashboardCmd.Flags().Lookup("host")
				if hostFlag == nil {
					return fmt.Errorf("expected a --host flag on `damping dashboard`")
				}
				if hostFlag.DefValue != "127.0.0.1" {
					return fmt.Errorf("expected --host to default to 127.0.0.1, got %q", hostFlag.DefValue)
				}
				return nil
			})
			sc.Then(`^no unauthenticated network peer should be able to reach the audit log$`, func() error {
				// Binding to 127.0.0.1 alone doesn't stop a DNS-rebinding
				// attack — a malicious webpage's browser can resolve its own
				// domain to 127.0.0.1 mid-session and still send that
				// domain as the Host header. Simulating exactly that
				// forged-Host request here is what actually proves this
				// scenario's title, not just re-asserting the bind address
				// (see cli/dashboard/server.go's Host-header check).
				req, err := http.NewRequest(http.MethodGet, w.httpServer.URL+"/api/summary", nil) // #nosec G107 -- w.httpServer.URL is this test's own httptest server, never external input
				if err != nil {
					return err
				}
				req.Host = "attacker.example"
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return err
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusForbidden {
					return fmt.Errorf("expected a forged Host header to be rejected, got %d", resp.StatusCode)
				}
				return nil
			})
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{localDashboardFeaturePath(t)},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
