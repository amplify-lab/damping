package compliance

import (
	"strings"
	"testing"
	"time"

	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

func mustEvent(t *testing.T, ts time.Time, actor, identity string, ch event.Channel, target string, risk event.RiskLevel, ruleID string, verdict, resolved decision.Verdict) event.ActionEvent {
	t.Helper()
	return event.ActionEvent{
		EventID:    "evt_" + actor + "_" + target,
		Timestamp:  ts,
		SessionID:  "sess_" + actor,
		Actor:      actor,
		Identity:   identity,
		Channel:    ch,
		ActionType: event.ActionShellExec,
		Target:     target,
		Raw:        target,
		RiskLevel:  risk,
		Decision: decision.Decision{
			Verdict:         verdict,
			ResolvedVerdict: resolved,
			PolicyID:        ruleID,
			Reason:          "test reason for " + ruleID,
		},
	}
}

func TestGenerate_CountsAndHighRiskFiltering(t *testing.T) {
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	events := []event.ActionEvent{
		mustEvent(t, now, "alice", "alice@bank.tw", event.ChannelCLI, "rm -rf /prod", event.RiskCritical, "destructive.rm_rf_protected", decision.Prompt, decision.Deny),
		mustEvent(t, now, "bob", "bob@bank.tw", event.ChannelCLI, "git status", event.RiskLow, "", decision.Allow, ""),
		mustEvent(t, now, "carol", "carol@bank.tw", event.ChannelMCP, "filesystem.delete_all", event.RiskHigh, "mcp.destructive_tool_call", decision.Deny, ""),
	}

	r := Generate(events, false)

	if r.TotalActions != 3 {
		t.Fatalf("expected TotalActions=3, got %d", r.TotalActions)
	}
	if r.RiskCounts[event.RiskCritical] != 1 || r.RiskCounts[event.RiskLow] != 1 || r.RiskCounts[event.RiskHigh] != 1 {
		t.Fatalf("expected one event per risk tier present, got %+v", r.RiskCounts)
	}
	// Only the critical + high entries belong in the high-risk detail
	// section — the low-risk "git status" allow must not clutter it, per
	// features/compliance_report_demo.feature's explicit scenario.
	if len(r.HighRiskEntries) != 2 {
		t.Fatalf("expected 2 high-risk-or-critical entries, got %d: %+v", len(r.HighRiskEntries), r.HighRiskEntries)
	}
	for _, e := range r.HighRiskEntries {
		if e.RiskLevel != event.RiskCritical && e.RiskLevel != event.RiskHigh {
			t.Fatalf("a low-risk entry leaked into HighRiskEntries: %+v", e)
		}
	}
}

func TestGenerate_OutcomeUsesResolvedVerdictNotRawVerdict(t *testing.T) {
	now := time.Now()
	events := []event.ActionEvent{
		mustEvent(t, now, "alice", "alice@bank.tw", event.ChannelCLI, "rm -rf /prod", event.RiskCritical, "destructive.rm_rf_protected", decision.Prompt, decision.Deny),
	}
	r := Generate(events, false)
	if len(r.HighRiskEntries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(r.HighRiskEntries))
	}
	if r.HighRiskEntries[0].Outcome != string(decision.Deny) {
		t.Fatalf("expected outcome to reflect the resolved verdict (deny), got %q", r.HighRiskEntries[0].Outcome)
	}
	if r.OutcomeCounts[string(decision.Deny)] != 1 {
		t.Fatalf("expected OutcomeCounts to count by resolved outcome, got %+v", r.OutcomeCounts)
	}
}

func TestGenerate_EmptyHighRiskSetIsExplicit(t *testing.T) {
	events := []event.ActionEvent{
		mustEvent(t, time.Now(), "alice", "", event.ChannelCLI, "git status", event.RiskLow, "", decision.Allow, ""),
	}
	r := Generate(events, false)
	if len(r.HighRiskEntries) != 0 {
		t.Fatalf("expected zero high-risk entries, got %d", len(r.HighRiskEntries))
	}
	md := r.RenderMarkdown()
	if !strings.Contains(md, "No high-risk or critical actions") {
		t.Fatalf("expected an explicit 'no high-risk actions' statement, not silence, got:\n%s", md)
	}
}

func TestReport_RenderMarkdown_DiscloseDemoAndScopeLimits(t *testing.T) {
	r := Generate(nil, true)
	md := r.RenderMarkdown()
	if !strings.Contains(md, "demo") && !strings.Contains(md, "synthetic") {
		t.Fatalf("expected the demo report to disclose it's built on synthetic/demo data, got:\n%s", md)
	}
	if !strings.Contains(md, "not an official") {
		t.Fatalf("expected disclosure that this isn't an official regulator template, got:\n%s", md)
	}
	if !strings.Contains(md, "Phase 5") {
		t.Fatalf("expected disclosure that this isn't the full Phase 5 enterprise report, got:\n%s", md)
	}
}

func TestReport_RenderMarkdown_NonDemoDoesNotClaimToBeDemo(t *testing.T) {
	r := Generate(nil, false)
	md := r.RenderMarkdown()
	if strings.Contains(md, "synthetic 30-day") {
		t.Fatalf("a real (non-demo) report must not claim to be built on synthetic data, got:\n%s", md)
	}
}

func TestReport_RenderJSON_RoundTrips(t *testing.T) {
	events := []event.ActionEvent{
		mustEvent(t, time.Now(), "alice", "alice@bank.tw", event.ChannelCLI, "rm -rf /prod", event.RiskCritical, "destructive.rm_rf_protected", decision.Prompt, decision.Deny),
	}
	r := Generate(events, false)
	data, err := r.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !strings.Contains(string(data), "destructive.rm_rf_protected") {
		t.Fatalf("expected the matched rule id in JSON output, got: %s", data)
	}
}

func TestGenerate_RiskOverTimeBucketsByCalendarDayInChronologicalOrder(t *testing.T) {
	day1 := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	day1Later := time.Date(2026, 7, 1, 20, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 7, 2, 9, 0, 0, 0, time.UTC)
	events := []event.ActionEvent{
		mustEvent(t, day2, "alice", "", event.ChannelCLI, "x", event.RiskHigh, "r1", decision.Deny, ""),
		mustEvent(t, day1, "alice", "", event.ChannelCLI, "x", event.RiskLow, "", decision.Allow, ""),
		mustEvent(t, day1Later, "alice", "", event.ChannelCLI, "x", event.RiskCritical, "r2", decision.Deny, ""),
	}
	r := Generate(events, false)
	if len(r.RiskOverTime) != 2 {
		t.Fatalf("expected events on two distinct calendar days to produce 2 buckets, got %d: %+v", len(r.RiskOverTime), r.RiskOverTime)
	}
	if !r.RiskOverTime[0].Date.Before(r.RiskOverTime[1].Date) {
		t.Fatalf("expected buckets in chronological order, got %+v", r.RiskOverTime)
	}
	if r.RiskOverTime[0].Low != 1 || r.RiskOverTime[0].Critical != 1 {
		t.Fatalf("expected day 1's bucket to combine both same-day events (low=1, critical=1), got %+v", r.RiskOverTime[0])
	}
	if r.RiskOverTime[1].High != 1 {
		t.Fatalf("expected day 2's bucket to have high=1, got %+v", r.RiskOverTime[1])
	}
}

func TestGenerate_TopRulesExcludesPlainAllowsAndSortsDescending(t *testing.T) {
	now := time.Now()
	events := []event.ActionEvent{
		mustEvent(t, now, "alice", "", event.ChannelCLI, "x", event.RiskCritical, "destructive.rm_rf_protected", decision.Deny, ""),
		mustEvent(t, now, "alice", "", event.ChannelCLI, "x", event.RiskCritical, "destructive.rm_rf_protected", decision.Deny, ""),
		mustEvent(t, now, "alice", "", event.ChannelCLI, "x", event.RiskHigh, "destructive.git_push_force", decision.Deny, ""),
		mustEvent(t, now, "bob", "", event.ChannelCLI, "git status", event.RiskLow, "", decision.Allow, ""),
	}
	r := Generate(events, false)
	if len(r.TopRules) != 2 {
		t.Fatalf("expected 2 distinct rule ids (plain allow excluded), got %+v", r.TopRules)
	}
	if r.TopRules[0].RuleID != "destructive.rm_rf_protected" || r.TopRules[0].Count != 2 {
		t.Fatalf("expected the most-triggered rule first, got %+v", r.TopRules[0])
	}
}

func TestGenerate_CriticalDeniedAndDeniedCounts(t *testing.T) {
	now := time.Now()
	events := []event.ActionEvent{
		mustEvent(t, now, "alice", "", event.ChannelCLI, "x", event.RiskCritical, "r1", decision.Deny, ""),
		mustEvent(t, now, "alice", "", event.ChannelCLI, "x", event.RiskHigh, "r2", decision.Deny, ""),
		mustEvent(t, now, "alice", "", event.ChannelCLI, "x", event.RiskCritical, "r3", decision.Prompt, decision.Allow),
		mustEvent(t, now, "bob", "", event.ChannelCLI, "git status", event.RiskLow, "", decision.Allow, ""),
	}
	r := Generate(events, false)
	if r.DeniedCount != 2 {
		t.Fatalf("expected DeniedCount=2 (using resolved outcome, not raw verdict), got %d", r.DeniedCount)
	}
	if r.CriticalDeniedCount != 1 {
		t.Fatalf("expected CriticalDeniedCount=1 (only the critical entry actually denied), got %d", r.CriticalDeniedCount)
	}
}

func TestReport_RenderText_IsHumanReadableTable(t *testing.T) {
	events := []event.ActionEvent{
		mustEvent(t, time.Now(), "alice", "alice@bank.tw", event.ChannelCLI, "rm -rf /prod", event.RiskCritical, "destructive.rm_rf_protected", decision.Prompt, decision.Deny),
	}
	r := Generate(events, false)
	txt := r.RenderText()
	if !strings.Contains(txt, "alice") || !strings.Contains(txt, "destructive.rm_rf_protected") {
		t.Fatalf("expected the text render to include actor and rule id, got:\n%s", txt)
	}
}
