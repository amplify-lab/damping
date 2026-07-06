package dashboard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amplify-lab/damping/cli/policies"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

func sampleEvent(sessionID, actor string, channel event.Channel, risk event.RiskLevel, d decision.Decision) event.ActionEvent {
	return event.ActionEvent{
		EventID:    "evt_" + sessionID + "_" + string(risk),
		Timestamp:  time.Now(),
		SessionID:  sessionID,
		Actor:      actor,
		Channel:    channel,
		ActionType: event.ActionShellExec,
		Target:     "rm",
		Raw:        "rm -rf ~/",
		RiskLevel:  risk,
		Decision:   d,
	}
}

func newTestServer(t *testing.T, policyContent string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	policyPath := filepath.Join(dir, "policy.yaml")
	if policyContent != "" {
		if err := os.WriteFile(policyPath, []byte(policyContent), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return NewServer(Config{AuditPath: auditPath, PolicyPath: policyPath}), auditPath
}

// newLocalRequest builds a GET request the way a real browser would send
// one to this server — httptest.NewRequest defaults Host to "example.com",
// which the Host-header check (server.go) correctly rejects; tests need a
// real local Host to exercise the handlers themselves rather than that
// check. TestHostHeaderCheck below exercises the rejection path directly.
func newLocalRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "127.0.0.1"
	return req
}

func TestHandleIndex_ServesHTML(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("expected text/html content type, got %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "damping") {
		t.Fatalf("expected the page to mention damping, got: %s", rec.Body.String())
	}
}

func TestHandleCSS_ServesCompiledStylesheet(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/static/dashboard.css"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("expected text/css content type, got %q", rec.Header().Get("Content-Type"))
	}
	if rec.Body.Len() == 0 {
		t.Fatal("expected a non-empty compiled stylesheet")
	}
}

func TestHandleChartsJS_ServesEmbeddedScript(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/static/charts.js"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("expected a javascript content type, got %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "DampingCharts") {
		t.Fatalf("expected the DampingCharts namespace in the served script, got: %s", rec.Body.String())
	}
}

func TestHandleSummary_ReportsRuleCountAndAgents(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/summary"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got summary
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding summary: %v", err)
	}
	if !got.Enabled {
		t.Fatal("expected enabled=true (no disabled marker in a fresh temp env)")
	}
	if got.RuleCount == 0 {
		t.Fatalf("expected a non-zero rule count from the default policy, got %+v", got)
	}
	if got.PolicyError != "" {
		t.Fatalf("expected no policy error, got %q", got.PolicyError)
	}
}

// TestHandleSummary_ReportsPolicyLoadFailure is a regression-shaped test for
// the same failure mode `damping status` warns about (cli/cmd/status.go) —
// the dashboard's summary panel must surface it too, not silently show a
// healthy-looking rule count of 0.
func TestHandleSummary_ReportsPolicyLoadFailure(t *testing.T) {
	s, _ := newTestServer(t, "") // no policy file written at all
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/summary"))
	var got summary
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding summary: %v", err)
	}
	if got.PolicyError == "" {
		t.Fatalf("expected a policy_error for a missing policy file, got %+v", got)
	}
}

// TestHandleSummary_ReportsDegradedReadFailure is a regression test for a
// real false all-clear: handleSummary used to silently leave
// DegradedCount7d at its zero value on any audit.ReadAll error, unlike
// handleEvents (below), which correctly turns an identical error into an
// HTTP 500. A corrupted audit log should surface as an error field, not a
// healthy-looking "0 degraded events."
func TestHandleSummary_ReportsDegradedReadFailure(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	if err := os.WriteFile(auditPath, []byte("{not valid json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/summary"))
	var got summary
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding summary: %v", err)
	}
	if got.DegradedError == "" {
		t.Fatalf("expected a degraded_error for a corrupted audit log, got %+v", got)
	}
	if got.DegradedCount7d != 0 {
		t.Fatalf("expected DegradedCount7d to stay at 0 (not a fabricated count) when the read failed, got %d", got.DegradedCount7d)
	}
}

func TestHandleEvents_EmptyLogReturnsEmptyArrayNotNull(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/events"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// "null" would force every client to special-case it before .length/.map
	// works — see index.html's renderEvents, which treats [] as the signal
	// for the brand's own empty-state copy ("nothing to dampen").
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("expected a literal empty JSON array, got: %s", rec.Body.String())
	}
}

func TestHandleEvents_FiltersByRisk(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	mustAppend := func(e event.ActionEvent) {
		t.Helper()
		if err := w.Append(e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	mustAppend(sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskCritical, decision.Decision{Verdict: decision.Deny}))
	mustAppend(sampleEvent("s2", "cursor", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow}))

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/events?risk=critical"))
	var got []event.ActionEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding events: %v", err)
	}
	if len(got) != 1 || got[0].SessionID != "s1" {
		t.Fatalf("expected exactly the critical-risk event, got %+v", got)
	}
}

func TestHandleEvents_InvalidSinceReturnsBadRequest(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/events?since=not-a-duration"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unparseable since, got %d", rec.Code)
	}
}

// TestHandleEvents_DefaultLimitCapsResults is a regression test for a gap
// found via a deeper look at CLI/dashboard parity: `damping log --limit`
// exists, but /api/events had no equivalent at all, so a long-lived
// install's entire audit history got sent to the browser on every request.
// Unlike the CLI (whose own --limit defaults to 0/unbounded, fine for a
// terminal), this endpoint now defaults to defaultEventsLimit since its
// response gets re-rendered as DOM rows on every filter change.
func TestHandleEvents_DefaultLimitCapsResults(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	total := defaultEventsLimit + 5
	for i := 0; i < total; i++ {
		ev := sampleEvent("s", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})
		ev.EventID = fmt.Sprintf("evt_%03d", i)
		if err := w.Append(ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/events"))
	var got []event.ActionEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding events: %v", err)
	}
	if len(got) != defaultEventsLimit {
		t.Fatalf("expected the default limit (%d) to cap the response, got %d events", defaultEventsLimit, len(got))
	}
	if got[len(got)-1].EventID != fmt.Sprintf("evt_%03d", total-1) {
		t.Fatalf("expected the kept events to be the most recent ones, got last=%s", got[len(got)-1].EventID)
	}
	if rec.Header().Get("X-Damping-Truncated") != "true" {
		t.Fatal("expected X-Damping-Truncated: true when the default cap actually dropped events — see index.html's truncated-note, and docs/ux-dashboard-spec.md §4's 'never silently drop data'")
	}
}

func TestHandleEvents_NoTruncationHeaderWhenNothingWasDropped(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	if err := w.Append(sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})); err != nil {
		t.Fatalf("append: %v", err)
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/events"))
	if rec.Header().Get("X-Damping-Truncated") == "true" {
		t.Fatal("expected no truncation header when every event fits under the default limit")
	}
}

func TestHandleEvents_ExplicitLimitOverridesDefault(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	for i := 0; i < 5; i++ {
		ev := sampleEvent("s", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})
		ev.EventID = fmt.Sprintf("evt_%d", i)
		if err := w.Append(ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/events?limit=2"))
	var got []event.ActionEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding events: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 events for ?limit=2, got %d", len(got))
	}
}

func TestHandleEvents_ExplicitZeroLimitMeansUnlimited(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	total := defaultEventsLimit + 5
	for i := 0; i < total; i++ {
		ev := sampleEvent("s", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})
		ev.EventID = fmt.Sprintf("evt_%03d", i)
		if err := w.Append(ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/events?limit=0"))
	var got []event.ActionEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding events: %v", err)
	}
	if len(got) != total {
		t.Fatalf("expected ?limit=0 to mean unlimited (matching damping log's vocabulary), got %d of %d", len(got), total)
	}
}

func TestHandleEvents_InvalidLimitReturnsBadRequest(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/events?limit=not-a-number"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unparseable limit, got %d", rec.Code)
	}
}

func TestHandleSessions_GroupsAndOrdersMostRecentFirst(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	mustAppend := func(e event.ActionEvent) {
		t.Helper()
		if err := w.Append(e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// s1 is active first and is still spiking (its last point is its worst
	// risk yet); s2 is active more recently and has settled (its last point
	// is its best) — s2 should sort first by recency, independent of which
	// one is actually settled.
	mustAppend(sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow}))
	mustAppend(sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskCritical, decision.Decision{Verdict: decision.Deny}))
	mustAppend(sampleEvent("s2", "cursor", event.ChannelCLI, event.RiskHigh, decision.Decision{Verdict: decision.Prompt}))
	mustAppend(sampleEvent("s2", "cursor", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow}))

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/sessions"))
	var got []sessionSpark
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding sessions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 sessions, got %+v", got)
	}
	if got[0].SessionID != "s2" {
		t.Fatalf("expected the most-recently-active session (s2) first, got %+v", got)
	}
	if !got[0].Settled {
		t.Fatalf("expected s2 (critical/high -> low) to be settled, got %+v", got[0])
	}
	if got[1].Settled {
		t.Fatalf("expected s1 (low -> critical, still spiking) to NOT be settled, got %+v", got[1])
	}
}

// TestHandleSessions_OrdersByLastActivityWhenSessionsInterleave is a
// regression test for a real bug a review caught: an earlier version
// ordered by each session's FIRST-seen position (reversed), which only
// happens to equal "most recently active" when sessions never interleave —
// exactly the case the sibling test above covers, which is why it didn't
// catch this. Here "old" starts first, "new" starts and settles entirely in
// between, and "old" then resumes with the single most recent, highest-risk
// event in the whole log — "old" must still sort first.
func TestHandleSessions_OrdersByLastActivityWhenSessionsInterleave(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	mustAppend := func(e event.ActionEvent) {
		t.Helper()
		if err := w.Append(e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	mustAppend(sampleEvent("old", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow}))
	mustAppend(sampleEvent("new", "cursor", event.ChannelCLI, event.RiskHigh, decision.Decision{Verdict: decision.Prompt}))
	mustAppend(sampleEvent("new", "cursor", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow}))
	mustAppend(sampleEvent("old", "claude-code", event.ChannelCLI, event.RiskCritical, decision.Decision{Verdict: decision.Deny}))

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/sessions"))
	var got []sessionSpark
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding sessions: %v", err)
	}
	if len(got) != 2 || got[0].SessionID != "old" {
		t.Fatalf("expected 'old' (most recently active, despite starting first) sorted first, got %+v", got)
	}
	if got[0].Settled {
		t.Fatalf("expected 'old' (low -> critical, still spiking) to NOT be settled, got %+v", got[0])
	}
	if got[1].SessionID != "new" || !got[1].Settled {
		t.Fatalf("expected 'new' (high -> low, settled) second, got %+v", got[1])
	}
}

// TestHandleEventStream_EmitsNewlyAppendedEvent is a regression test for a
// real bug a manual browser walkthrough caught: handleEventStream used to
// call audit.Follow with a hardcoded startOffset of 0, replaying the
// dashboard's *entire* pre-existing audit history down the stream as if
// every event were brand new — since the client's initial /api/events
// fetch already rendered those same events, every row appeared twice on
// screen. A pre-existing event is appended here before the stream even
// opens, specifically to catch that regression: the stream must emit only
// the event appended after it opens, never the earlier one.
func TestHandleEventStream_EmitsNewlyAppendedEvent(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	if err := w.Append(sampleEvent("pre-existing", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})); err != nil {
		t.Fatalf("append: %v", err)
	}

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("opening stream: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Give the handler a moment to start polling before we append — Follow
	// polls every 500ms starting from the file's size at call time (see
	// core/audit.Follow's own tests for the same pattern).
	time.Sleep(50 * time.Millisecond)
	if err := w.Append(sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskHigh, decision.Decision{Verdict: decision.Deny})); err != nil {
		t.Fatalf("append: %v", err)
	}

	scanner := bufio.NewScanner(resp.Body)
	deadline := time.Now().Add(4 * time.Second)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			var got event.ActionEvent
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &got); err != nil {
				t.Fatalf("decoding SSE payload: %v", err)
			}
			if got.SessionID == "pre-existing" {
				t.Fatalf("stream replayed the pre-existing event — startOffset regression, got %+v", got)
			}
			if got.SessionID != "s1" {
				t.Fatalf("expected the appended event's session, got %+v", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the SSE event")
		}
	}
	t.Fatal("stream closed before emitting the appended event")
}

// TestHostHeaderCheck_RejectsForgedHost is a regression test for a real gap
// a review found: binding to 127.0.0.1 alone doesn't stop a malicious
// webpage from reading this unauthenticated server via DNS rebinding — the
// browser resolves an attacker's own domain to 127.0.0.1 mid-session and
// then treats the connection as same-origin with that domain. The Host
// header on such a request still carries the attacker's domain, never a
// real local address, which is exactly what this check rejects.
func TestHostHeaderCheck_RejectsForgedHost(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	req.Host = "attacker.example" // httptest.NewRequest would otherwise default to "example.com" — same class of forged host, made explicit here
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected a forged Host header to be rejected with 403, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/summary"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected a genuine 127.0.0.1 Host header to be allowed, got %d", rec.Code)
	}
}

// TestHostHeaderCheck_SkipsEnforcementWhenExplicitlyBoundElsewhere confirms
// the check steps aside once the operator has explicitly chosen a
// non-default bind host (already loudly warned about at startup, see
// cli/cmd/dashboard.go) — there's no single correct Host value to
// allowlist against a bind-all address, so this is a deliberate, narrow
// exception, not a hole: it only ever applies after that explicit choice.
func TestHostHeaderCheck_SkipsEnforcementWhenExplicitlyBoundElsewhere(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(Config{
		AuditPath:  filepath.Join(dir, "audit.jsonl"),
		PolicyPath: filepath.Join(dir, "policy.yaml"),
		BindHost:   "0.0.0.0",
	})
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(policies.Default), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	req.Host = "whatever.example"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the Host check to step aside for an explicit non-local BindHost, got %d", rec.Code)
	}
}
