package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amplify-lab/damping/cli/policies"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

// TestComputeStats_CountsOutcomesAndDegradedSeparately mirrors printEvent's
// existing convention (cli/cmd/log.go): Degraded is an orthogonal flag, not
// a third outcome value — a degraded event's Outcome() is still "allow", so
// it must be counted in both places, not one or the other.
func TestComputeStats_CountsOutcomesAndDegradedSeparately(t *testing.T) {
	events := []event.ActionEvent{
		sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskCritical, decision.Decision{Verdict: decision.Deny}),
		sampleEvent("s2", "cursor", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow}),
		sampleEvent("s3", "cursor", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow, Degraded: true}),
	}
	got := computeStats(events, audit.Filter{})
	if got.TotalEvents != 3 {
		t.Errorf("expected TotalEvents 3, got %d", got.TotalEvents)
	}
	if got.OutcomeCounts.Allow != 2 {
		t.Errorf("expected 2 allows, got %d", got.OutcomeCounts.Allow)
	}
	if got.OutcomeCounts.Deny != 1 {
		t.Errorf("expected 1 deny, got %d", got.OutcomeCounts.Deny)
	}
	if got.OutcomeCounts.Degraded != 1 {
		t.Errorf("expected 1 degraded, got %d", got.OutcomeCounts.Degraded)
	}
}

func TestComputeStats_TopRulesExcludesPlainAllowsAndSortsDescending(t *testing.T) {
	mk := func(policyID string, risk event.RiskLevel) event.ActionEvent {
		e := sampleEvent("s1", "claude-code", event.ChannelCLI, risk, decision.Decision{Verdict: decision.Deny, PolicyID: policyID, Risk: string(risk)})
		return e
	}
	events := []event.ActionEvent{
		mk("destructive.rm_rf_protected", event.RiskCritical),
		mk("destructive.rm_rf_protected", event.RiskCritical),
		mk("destructive.git_push_force", event.RiskHigh),
		sampleEvent("s2", "cursor", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow}), // no PolicyID: a plain allow
	}
	got := computeStats(events, audit.Filter{})
	if len(got.TopRules) != 2 {
		t.Fatalf("expected exactly 2 distinct rule ids (plain allow excluded), got %+v", got.TopRules)
	}
	if got.TopRules[0].PolicyID != "destructive.rm_rf_protected" || got.TopRules[0].Count != 2 {
		t.Errorf("expected the most-triggered rule first, got %+v", got.TopRules[0])
	}
	if got.TopRules[1].PolicyID != "destructive.git_push_force" || got.TopRules[1].Count != 1 {
		t.Errorf("expected the second rule next, got %+v", got.TopRules[1])
	}
}

func TestComputeStats_TopRulesCapsAtTen(t *testing.T) {
	var events []event.ActionEvent
	for i := 0; i < 15; i++ {
		id := "rule." + string(rune('a'+i))
		events = append(events, sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskHigh, decision.Decision{Verdict: decision.Deny, PolicyID: id, Risk: string(event.RiskHigh)}))
	}
	got := computeStats(events, audit.Filter{})
	if len(got.TopRules) != 10 {
		t.Fatalf("expected TopRules capped at 10, got %d", len(got.TopRules))
	}
}

// TestComputeStats_RiskOverTimeBucketsEveryEvent is a coarse invariant check
// (not pinning the exact bucket count/width, which is an implementation
// detail): every event must land in exactly one bucket, so the sum of all
// per-tier bucket counts across the whole series always equals the input
// length — a real risk of an off-by-one at the boundary silently dropping
// the first or last event.
func TestComputeStats_RiskOverTimeBucketsEveryEvent(t *testing.T) {
	now := time.Now()
	events := []event.ActionEvent{
		sampleEvent("s1", "a", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow}),
		sampleEvent("s2", "a", event.ChannelCLI, event.RiskMedium, decision.Decision{Verdict: decision.Allow}),
		sampleEvent("s3", "a", event.ChannelCLI, event.RiskHigh, decision.Decision{Verdict: decision.Deny}),
		sampleEvent("s4", "a", event.ChannelCLI, event.RiskCritical, decision.Decision{Verdict: decision.Deny}),
	}
	events[0].Timestamp = now.Add(-3 * time.Hour)
	events[1].Timestamp = now.Add(-2 * time.Hour)
	events[2].Timestamp = now.Add(-1 * time.Hour)
	events[3].Timestamp = now

	got := computeStats(events, audit.Filter{})
	sum := 0
	for _, b := range got.RiskOverTime {
		sum += b.Low + b.Medium + b.High + b.Critical
	}
	if sum != len(events) {
		t.Fatalf("expected every event to land in exactly one bucket (sum=%d), got sum=%d across %d buckets", len(events), sum, len(got.RiskOverTime))
	}
}

func TestComputeStats_EmptyEventsProducesZeroValueNotError(t *testing.T) {
	got := computeStats(nil, audit.Filter{})
	if got.TotalEvents != 0 {
		t.Errorf("expected TotalEvents 0 for no events, got %d", got.TotalEvents)
	}
	if got.TopRules == nil {
		t.Error("expected TopRules to be a non-nil empty slice (never JSON null), got nil")
	}
	if got.RiskOverTime == nil {
		t.Error("expected RiskOverTime to be a non-nil empty slice (never JSON null), got nil")
	}
}

// TestHandleStats_ComputesOverFullHistoryNotEventsLimit is the whole point
// of this endpoint existing separately from /api/events: that endpoint caps
// at defaultEventsLimit (200) by default so the live table stays fast, but
// stats meant to summarize "what happened this month" must never silently
// undercount because more than 200 events happened.
func TestHandleStats_ComputesOverFullHistoryNotEventsLimit(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	for i := 0; i < defaultEventsLimit+25; i++ {
		if err := w.Append(sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/stats"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got stats
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding stats: %v", err)
	}
	if got.TotalEvents != defaultEventsLimit+25 {
		t.Fatalf("expected TotalEvents to reflect the full history (%d), got %d", defaultEventsLimit+25, got.TotalEvents)
	}
}

func TestHandleStats_RespectsFilterQuery(t *testing.T) {
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
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/stats?risk=critical"))
	var got stats
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding stats: %v", err)
	}
	if got.TotalEvents != 1 {
		t.Fatalf("expected the risk=critical filter to narrow to 1 event, got %d", got.TotalEvents)
	}
}

func TestHandleStats_InvalidFilterReturnsBadRequest(t *testing.T) {
	s, _ := newTestServer(t, policies.Default)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newLocalRequest("/api/stats?since=not-a-duration"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unparseable since, got %d", rec.Code)
	}
}
