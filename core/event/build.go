package event

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/amplify-lab/damping/core/decision"
)

// NewID generates a random event identifier — the standard way every
// adapter mints EventID before calling New.
func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "evt_" + hex.EncodeToString(b)
}

// New constructs an ActionEvent from primitive pieces plus a policy
// decision, deriving RiskLevel from the decision. This is the one standard
// construction path every adapter uses — see cli/adapter/hook.BuildActionEvent
// (CLI) and cli/adapter/mcp (MCP) for the thin per-channel wrappers around
// it. Centralizing this here (rather than duplicating risk-derivation logic
// per adapter) is what keeps "same risk mapping regardless of channel" true
// by construction.
//
// Prefers d.Risk — the matched rule's own declared risk level from
// cli/policies/default.yaml (e.g. "critical" for rm_rf_protected) — over a
// generic verdict-based guess. A review found the previous verdict-only
// mapping (deny→critical, prompt→high, allow→low) silently discarded the
// real per-rule classification for any rule whose declared risk didn't
// happen to match its action tier's default: 5 of the 11 shipped rules
// diverged, including rm_rf_protected itself (declared critical, always
// logged as high) and write_protected_path (same). Every `damping log
// --risk critical` / dashboard risk filter and Phase 5 compliance report
// this schema is designed for depends on RiskLevel actually reflecting the
// rule that fired, not just which action tier it happened to map to. The
// verdict-based fallback still applies when d.Risk is empty — a plain
// allow with no rule matched, an always-allow/deny pattern match, or a
// hand-built degraded Decision, none of which carry a rule's own risk.
func New(eventID, sessionID, actor string, channel Channel, actionType ActionType, target, raw string, d decision.Decision) ActionEvent {
	risk := RiskLow
	switch d.Verdict {
	case decision.Deny:
		risk = RiskCritical
	case decision.Prompt:
		risk = RiskHigh
	}
	if d.Risk != "" {
		risk = RiskLevel(d.Risk)
	}
	return ActionEvent{
		EventID:    eventID,
		Timestamp:  time.Now(),
		SessionID:  sessionID,
		Actor:      actor,
		Channel:    channel,
		ActionType: actionType,
		Target:     target,
		Raw:        raw,
		RiskLevel:  risk,
		Decision:   d,
	}
}
