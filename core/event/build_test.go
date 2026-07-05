package event

import (
	"testing"

	"github.com/amplify-lab/damping/core/decision"
)

func TestNewID_NeverEmpty(t *testing.T) {
	if id := NewID(); id == "" {
		t.Fatal("expected a non-empty event ID")
	}
}

// TestNew_PrefersDecisionRiskOverVerdictGuess is a regression test for a
// real bug: New() used to derive RiskLevel purely from the decision's
// Verdict (deny→critical, prompt→high, allow→low), silently discarding the
// matched rule's own declared risk level whenever it didn't happen to match
// that guess. In the shipped default policy, 5 of 11 rules diverge — e.g.
// destructive.rm_rf_protected is declared "critical" but has action
// "prompt", so every rm -rf interception was logged as risk_level "high",
// not "critical". Every `damping log --risk`/dashboard risk filter and any
// future compliance report depends on this being the rule's real risk.
func TestNew_PrefersDecisionRiskOverVerdictGuess(t *testing.T) {
	cases := []struct {
		name     string
		d        decision.Decision
		wantRisk RiskLevel
	}{
		{
			name:     "prompt verdict with a declared critical risk keeps critical, not the high a bare prompt would guess",
			d:        decision.Decision{Verdict: decision.Prompt, PolicyID: "destructive.rm_rf_protected", Risk: "critical"},
			wantRisk: RiskCritical,
		},
		{
			name:     "prompt verdict with a declared medium risk keeps medium, not the high a bare prompt would guess",
			d:        decision.Decision{Verdict: decision.Prompt, PolicyID: "destructive.chmod_777_recursive", Risk: "medium"},
			wantRisk: RiskMedium,
		},
		{
			name:     "deny verdict with a declared critical risk still matches (no divergence for this rule, but must not regress)",
			d:        decision.Decision{Verdict: decision.Deny, PolicyID: "self_protection.damping_off_attempt", Risk: "critical"},
			wantRisk: RiskCritical,
		},
		{
			name:     "empty Risk (no rule matched — a plain allow) falls back to the verdict-based guess",
			d:        decision.Decision{Verdict: decision.Allow},
			wantRisk: RiskLow,
		},
		{
			name:     "empty Risk on a deny (always-deny pattern match, not a rule) falls back to critical",
			d:        decision.Decision{Verdict: decision.Deny, Reason: "matched an always-deny pattern"},
			wantRisk: RiskCritical,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := New("evt_1", "sess_1", "claude-code", ChannelCLI, ActionShellExec, "rm", "rm -rf ~/", tc.d)
			if ev.RiskLevel != tc.wantRisk {
				t.Fatalf("expected RiskLevel %q, got %q", tc.wantRisk, ev.RiskLevel)
			}
		})
	}
}
