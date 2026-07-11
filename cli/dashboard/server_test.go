package dashboard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amplify-lab/damping/cli/policies"
	"github.com/amplify-lab/damping/cli/update"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
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

func TestHandlePolicy_ReturnsFullRuleList(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/policy"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got []policy.RuleConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding rules: %v", err)
	}
	cfg, err := policy.ParseConfig([]byte(policies.Default))
	if err != nil {
		t.Fatalf("parsing default policy for comparison: %v", err)
	}
	if len(got) != len(cfg.Rules) {
		t.Fatalf("expected %d rules (the full default policy), got %d", len(cfg.Rules), len(got))
	}
	// Every rule must carry a real, non-empty description — that's the
	// entire point of this endpoint (the dashboard's "what does this
	// protect against" explainer has nothing to show otherwise).
	for _, r := range got {
		if r.ID == "" || r.Description == "" || r.Risk == "" || r.Action == "" {
			t.Fatalf("expected every rule to have id/description/risk/action populated, got %+v", r)
		}
	}
}

func TestHandlePolicy_ReportsLoadFailure(t *testing.T) {
	s, _ := newTestServer(t, "") // no policy file written at all
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/policy"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for a missing policy file, got %d", rec.Code)
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

func TestHandleEvents_FiltersByKeyword(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	mustAppend := func(e event.ActionEvent) {
		t.Helper()
		if err := w.Append(e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	e1 := sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})
	e1.Raw = "cd ~/projects/fangchan-xiuwei-v3 && git status"
	e2 := sampleEvent("s2", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})
	e2.Raw = "git log --oneline"
	mustAppend(e1)
	mustAppend(e2)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/events?keyword=fangchan"))
	var got []event.ActionEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding events: %v", err)
	}
	if len(got) != 1 || got[0].SessionID != "s1" {
		t.Fatalf("expected only the event mentioning fangchan, got %+v", got)
	}
}

// TestHandleEvents_FiltersBySessionID is the dashboard-level regression test
// for clicking a session card in the "Recent sessions" panel: the resulting
// ?session_id= request must scope the events table to just that session,
// the same way `damping log --session <id>` (via --actor/--since) already
// lets a terminal user narrow down manually.
func TestHandleEvents_FiltersBySessionID(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	mustAppend := func(e event.ActionEvent) {
		t.Helper()
		if err := w.Append(e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	mustAppend(sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow}))
	mustAppend(sampleEvent("s2", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow}))

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/events?session_id=s2"))
	var got []event.ActionEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding events: %v", err)
	}
	if len(got) != 1 || got[0].SessionID != "s2" {
		t.Fatalf("expected only s2's event, got %+v", got)
	}
}

// TestHandleEvents_BeforeCursorEnablesLoadOlderPagination is the dashboard-
// level regression test for the "load older" pattern: fetching with
// ?before=<oldest event already shown> must return the next page back in
// time without re-including that same boundary event (Before is exclusive —
// see audit.Filter's doc comment).
func TestHandleEvents_BeforeCursorEnablesLoadOlderPagination(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	base := time.Now().Add(-time.Hour)
	var oldest event.ActionEvent
	for i := 0; i < 5; i++ {
		ev := sampleEvent("s", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})
		ev.EventID = fmt.Sprintf("evt_%d", i)
		ev.Timestamp = base.Add(time.Duration(i) * time.Second)
		if err := w.Append(ev); err != nil {
			t.Fatalf("append: %v", err)
		}
		if i == 2 {
			oldest = ev // the "oldest of the currently-shown page" cursor
		}
	}

	rec := httptest.NewRecorder()
	// url.QueryEscape (not plain string concatenation) so the timestamp's own
	// "+"/":" characters — real for a non-UTC offset — survive query-string
	// decoding intact; a real browser's URLSearchParams does this
	// automatically, which a naive concatenation here would not reproduce.
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/events?before="+url.QueryEscape(oldest.Timestamp.Format(time.RFC3339Nano))))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got []event.ActionEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding events: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected exactly the 2 events strictly older than the cursor (evt_0, evt_1), got %d: %+v", len(got), got)
	}
	for _, e := range got {
		if e.EventID == oldest.EventID {
			t.Fatalf("expected the cursor event itself to be excluded (Before is exclusive), but got it back: %+v", e)
		}
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
	// s1 is active first and its last point is critical (still spiking);
	// s2 is active more recently and its last point is low — s2 should sort
	// first by recency, independent of either session's own risk trend.
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
	if got[0].LatestRisk != event.RiskLow {
		t.Fatalf("expected s2's latest risk to be low (its last event), got %+v", got[0])
	}
	if got[1].LatestRisk != event.RiskCritical {
		t.Fatalf("expected s1's latest risk to be critical (its last event), got %+v", got[1])
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
	if got[0].LatestRisk != event.RiskCritical {
		t.Fatalf("expected 'old's latest risk to be critical (its last event), got %+v", got[0])
	}
	if got[1].SessionID != "new" || got[1].LatestRisk != event.RiskLow {
		t.Fatalf("expected 'new' (latest risk low) second, got %+v", got[1])
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
// TestHandleVersion_ReportsShapeWithNoNetworkCall exercises GET /api/version
// end-to-end through httptest, matching how this file already tests every
// other /api/* route rather than just eyeballing the handler. It sets
// DAMPING_NO_UPDATE_CHECK so update.Check makes zero network calls (that
// env var's contract — see cli/update/update.go) and DAMPING_INSTALL_DIR to
// a fresh writable temp dir so update.CurrentMethod's NeedsElevation is
// deterministic across every machine this test runs on, not dependent on
// whatever the real /usr/local/bin's permissions happen to be.
func TestHandleVersion_ReportsShapeWithNoNetworkCall(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	s.cfg.Version = "v1.2.3"
	t.Setenv("DAMPING_NO_UPDATE_CHECK", "1")
	t.Setenv("DAMPING_INSTALL_DIR", t.TempDir())

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/version"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got versionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding version response: %v", err)
	}
	if got.Current != "v1.2.3" {
		t.Fatalf("expected current=%q, got %+v", "v1.2.3", got)
	}
	if got.Latest != "" || got.UpdateAvailable {
		t.Fatalf("expected no update info with DAMPING_NO_UPDATE_CHECK set, got %+v", got)
	}
	if got.GithubURL != githubURL {
		t.Fatalf("expected github_url=%q, got %q", githubURL, got.GithubURL)
	}
	switch got.Method {
	case "script", "brew", "windows":
	default:
		t.Fatalf("expected method to be one of script/brew/windows, got %q", got.Method)
	}
	if got.Command == "" {
		t.Fatal("expected a non-empty command string")
	}
	if got.CanAutoUpdate {
		t.Fatal("expected can_auto_update=false when update_available is false, regardless of NeedsElevation")
	}
}

// TestHandleUpdate_RejectsMissingDashboardHeader is the required regression
// test for this endpoint's actual CSRF defense — see dashboardHeader's doc
// comment in handlers.go for the full threat model (a malicious page's
// blind cross-origin POST, no DNS rebinding needed, that the Host-header
// check alone does not stop). A request with no X-Damping-Dashboard header
// must be rejected before anything else happens: no method detection, no
// in-flight flag set, no streaming response started, no self-update
// command ever run.
//
// Mutation-tested by hand: temporarily commenting out handleUpdate's header
// check made this test fail (it started asserting on whatever the next
// check down — NeedsElevation, in this sandbox's default unwritable
// /usr/local/bin — produced instead, with a distinct error message this
// test does not accept), confirming the test actually exercises the header
// gate and not some other rejection path. Restored afterward; this file's
// git history at this point reflects the check back in place.
func TestHandleUpdate_RejectsMissingDashboardHeader(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/update", nil)
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:54321" // must be loopback to reach the header check this test actually exercises — see TestHandleUpdate_RejectsNonLoopbackRemoteAddr for the check ahead of this one
	// Deliberately no X-Damping-Dashboard header set.
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for POST /api/update with no %s header, got %d: %s", dashboardHeader, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), dashboardHeader) {
		t.Fatalf("expected the rejection message to name the missing header specifically (not some other check), got: %s", rec.Body.String())
	}
	if s.updateInFlight.Load() {
		t.Fatal("updateInFlight was set even though the header check should have rejected before ever reaching it — an update may have started")
	}
	if strings.Contains(rec.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatal("expected a plain error response, not an SSE stream — the header check must reject before any streaming (and therefore update.Apply) begins")
	}
}

// TestHandleUpdate_RejectsWhenElevationNeeded confirms NeedsElevation is
// re-checked fresh, server-side (defense (c) in the task's own required
// list) rather than ever trusted from the client. DAMPING_INSTALL_DIR
// points at a path with a regular file (not a directory) as a parent
// segment — os.MkdirAll can never succeed against that for any user,
// including root, which is why this is deterministic across every machine
// this test runs on (mirrors cli/update/method_test.go's own
// nonWritableDir helper).
func TestHandleUpdate_RejectsWhenElevationNeeded(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	parent := t.TempDir()
	blocker := filepath.Join(parent, "blocked-by-a-file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing blocker file: %v", err)
	}
	t.Setenv("DAMPING_INSTALL_DIR", filepath.Join(blocker, "sub", "damping"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/update", nil)
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set(dashboardHeader, "1")
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when the install location needs elevated privileges, got %d: %s", rec.Code, rec.Body.String())
	}
	if s.updateInFlight.Load() {
		t.Fatal("updateInFlight was set even though the elevation check should have rejected first")
	}
}

// TestHandleUpdate_ConcurrentRequestGetsConflict is the regression test for
// defense (d): a second POST while one is already applying must get 409,
// never run a second install concurrently. update.CurrentMethod() always
// computes a real system command with no test seam to make it "hang," so
// this drives the in-flight guard directly (an accessible field within this
// package) rather than racing two real HTTP requests against a real
// installer process.
func TestHandleUpdate_ConcurrentRequestGetsConflict(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	t.Setenv("DAMPING_INSTALL_DIR", t.TempDir()) // deterministic NeedsElevation=false, so this exercises the in-flight guard specifically, not elevation

	if !s.updateInFlight.CompareAndSwap(false, true) {
		t.Fatal("expected to be able to mark a fresh Server's update as in-flight")
	}
	defer s.updateInFlight.Store(false)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/update", nil)
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set(dashboardHeader, "1")
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict while an update is already in-flight, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleUpdate_RejectsNonLoopbackRemoteAddr is the regression test for
// finding (2): binding to 0.0.0.0 doesn't just widen who can *reach* this
// dashboard, it widens who can POST /api/update at all — dashboardHeader's
// CSRF defense stops a browser-based cross-origin request, but does nothing
// against a plain curl from another machine on the LAN, which can set any
// header it likes. A request with a real, correct dashboardHeader but a
// non-loopback RemoteAddr must still be rejected, and rejected before the
// method/elevation/in-flight checks ever run.
func TestHandleUpdate_RejectsNonLoopbackRemoteAddr(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	t.Setenv("DAMPING_INSTALL_DIR", t.TempDir())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/update", nil)
	req.Host = "127.0.0.1"
	req.Header.Set(dashboardHeader, "1")
	req.RemoteAddr = "203.0.113.7:54321" // a real LAN/WAN peer, not this machine
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-loopback RemoteAddr even with a valid %s header, got %d: %s", dashboardHeader, rec.Code, rec.Body.String())
	}
	if s.updateInFlight.Load() {
		t.Fatal("updateInFlight was set even though the loopback check should have rejected first")
	}
}

// TestHandleUpdate_AllowsLoopbackIPv6RemoteAddr confirms the loopback check
// isn't IPv4-only ("127.0.0.1" string-matching would miss "::1", the address
// a dashboard bound to an IPv6 loopback listener would see). Marking the
// update in-flight beforehand short-circuits past the real
// update.CurrentMethod()/Apply — this test only cares that the loopback
// check itself lets ::1 through to the next check (the resulting 409 proves
// that; TestHandleUpdate_ConcurrentRequestGetsConflict already covers the
// 409 path's own behavior in detail).
func TestHandleUpdate_AllowsLoopbackIPv6RemoteAddr(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	t.Setenv("DAMPING_INSTALL_DIR", t.TempDir())

	if !s.updateInFlight.CompareAndSwap(false, true) {
		t.Fatal("expected to mark update in-flight")
	}
	defer s.updateInFlight.Store(false)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/update", nil)
	req.Host = "127.0.0.1"
	req.Header.Set(dashboardHeader, "1")
	req.RemoteAddr = "[::1]:54321"
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected the ::1 loopback RemoteAddr to pass the loopback check and reach the in-flight guard (409), got %d: %s", rec.Code, rec.Body.String())
	}
}

// withFakeUpdateMethod and withFakeApply substitute handlers.go's
// currentMethod/applyUpdate package vars for the duration of one test,
// restored via t.Cleanup — the seam that makes handleUpdate's success/
// failure streaming testable at all without ever running a real
// curl-pipe-sh/brew/powershell command.
func withFakeUpdateMethod(t *testing.T, m update.Method) {
	t.Helper()
	orig := currentMethod
	currentMethod = func() update.Method { return m }
	t.Cleanup(func() { currentMethod = orig })
}

func withFakeApply(t *testing.T, fn func(ctx context.Context, m update.Method, w io.Writer) error) {
	t.Helper()
	orig := applyUpdate
	applyUpdate = fn
	t.Cleanup(func() { applyUpdate = orig })
}

// newLoopbackUpdateRequest builds a POST /api/update request that clears
// every gate ahead of the one a given test cares about (loopback Host,
// loopback RemoteAddr, the dashboardHeader) — the shared setup for the
// success/failure streaming tests below, which are specifically about what
// happens once every prior gate has already passed.
func newLoopbackUpdateRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/update", nil)
	req.Host = "127.0.0.1"
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set(dashboardHeader, "1")
	return req
}

// TestHandleUpdate_StreamsSuccessDoneFrame closes finding (3)'s gap: the
// success/apply path — including the exact SSE "event: done" frame
// index.html's runUpdate keys its success/failure UI off of — previously had
// zero test coverage, since update.CurrentMethod/update.Apply always run a
// real self-update command with no seam to fake before currentMethod/
// applyUpdate existed.
func TestHandleUpdate_StreamsSuccessDoneFrame(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	withFakeUpdateMethod(t, update.Method{Kind: "script", NeedsElevation: false})
	withFakeApply(t, func(ctx context.Context, m update.Method, w io.Writer) error {
		_, _ = w.Write([]byte("downloading release archive"))
		_, _ = w.Write([]byte("verifying checksum"))
		return nil
	})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLoopbackUpdateRequest())

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	want := "data: downloading release archive\n\ndata: verifying checksum\n\nevent: done\ndata: {\"ok\":true}\n\n"
	if rec.Body.String() != want {
		t.Fatalf("SSE body =\n%q\nwant\n%q", rec.Body.String(), want)
	}
	if s.updateInFlight.Load() {
		t.Fatal("expected updateInFlight to be reset once Apply finished")
	}
}

// TestHandleUpdate_StreamsFailureDoneFrame is the failure-path counterpart:
// an "event: error" frame carrying the failure text, followed by the final
// "event: done" frame with ok:false and the same error message — the shape
// index.html's handleUpdateFrame relies on to show update_failure_note
// instead of update_success_note.
func TestHandleUpdate_StreamsFailureDoneFrame(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	withFakeUpdateMethod(t, update.Method{Kind: "script", NeedsElevation: false})
	withFakeApply(t, func(ctx context.Context, m update.Method, w io.Writer) error {
		_, _ = w.Write([]byte("downloading release archive"))
		return fmt.Errorf("running script update command: exit status 1")
	})

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLoopbackUpdateRequest())

	if rec.Code != http.StatusOK { // headers are already committed 200 by the time Apply can fail — failure surfaces as an SSE event, never an HTTP status
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	want := "data: downloading release archive\n\n" +
		"event: error\ndata: running script update command: exit status 1\n\n" +
		"event: done\ndata: {\"ok\":false,\"error\":\"running script update command: exit status 1\"}\n\n"
	if rec.Body.String() != want {
		t.Fatalf("SSE body =\n%q\nwant\n%q", rec.Body.String(), want)
	}
	if s.updateInFlight.Load() {
		t.Fatal("expected updateInFlight to be reset even after Apply failed")
	}
}

// TestHandleUpdate_AppliesUnderContextDecoupledFromClientDisconnect is the
// regression test for finding (1): a client disconnecting mid-update
// (closing the tab, network blip) cancels r.Context() — Apply must run
// under context.WithoutCancel(r.Context()) so that cancellation never
// reaches it, since this endpoint replaces the running binary and a
// half-applied update on cancel is worse than a client that never sees the
// result. reqCtx is cancelled *before* the handler ever runs (simulating a
// browser that's already gone by the time Apply starts), and the fake apply
// asserts its own ctx was never cancelled — deterministically (ctx.Err(),
// not a select racing two ready channels).
func TestHandleUpdate_AppliesUnderContextDecoupledFromClientDisconnect(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	withFakeUpdateMethod(t, update.Method{Kind: "script", NeedsElevation: false})
	withFakeApply(t, func(ctx context.Context, m update.Method, w io.Writer) error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("apply started with an already-cancelled context: %w", err)
		}
		_, _ = w.Write([]byte("done"))
		return nil
	})

	reqCtx, cancel := context.WithCancel(context.Background())
	cancel() // the client is already gone before the handler even runs
	req := newLoopbackUpdateRequest().WithContext(reqCtx)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `event: done`+"\n"+`data: {"ok":true}`) {
		t.Fatalf("expected a successful done frame (proving Apply ran to completion despite the cancelled request context), got: %s", rec.Body.String())
	}
}

// failingResponseWriter is a minimal http.ResponseWriter+http.Flusher whose
// Write always fails, the way writing to a connection the client already
// closed would — used to prove sseLineWriter.Write is genuinely
// best-effort (finding (1)'s second half): a write failure here must never
// propagate as an error, or update.Apply's underlying exec.Cmd would
// misread a gone client as the update itself having failed.
type failingResponseWriter struct{ header http.Header }

func (f *failingResponseWriter) Header() http.Header {
	if f.header == nil {
		f.header = http.Header{}
	}
	return f.header
}
func (f *failingResponseWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("broken pipe") }
func (f *failingResponseWriter) WriteHeader(int)           {}
func (f *failingResponseWriter) Flush()                    {}

func TestSSELineWriter_WriteIsBestEffortOnBrokenPipe(t *testing.T) {
	fw := &failingResponseWriter{}
	sw := sseLineWriter{w: fw, flusher: fw}

	n, err := sw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("expected sseLineWriter.Write to swallow a downstream write failure (best-effort), got err=%v", err)
	}
	if n != len("hello") {
		t.Fatalf("expected Write to report the full length regardless of the downstream failure, got n=%d", n)
	}
}

// TestSSELineWriter_FramesEachWriteAndStripsEmbeddedNewlines verifies the
// actual SSE framing primitive handleUpdate hands to update.Apply, in
// isolation — deliberately without ever invoking update.Apply/CurrentMethod
// themselves (which always compute a REAL self-update command; there is no
// test seam to swap in a fake one, and actually running the real one in a
// test would mean executing a live curl-pipe-sh/brew/powershell command).
// This exercises requirement (e) end to end instead: one "data: <line>\n\n"
// frame per Write call, flushed immediately, with embedded newlines in a
// single payload flattened rather than truncating the frame.
func TestSSELineWriter_FramesEachWriteAndStripsEmbeddedNewlines(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := sseLineWriter{w: rec, flusher: rec}

	if _, err := sw.Write([]byte("cloning release archive...")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := sw.Write([]byte("line one\nline two\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if !rec.Flushed {
		t.Fatal("expected each Write to flush, matching handleEventStream's own pattern")
	}
	want := "data: cloning release archive...\n\ndata: line one line two \n\n"
	if rec.Body.String() != want {
		t.Fatalf("sseLineWriter framing =\n%q\nwant\n%q", rec.Body.String(), want)
	}
}

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
