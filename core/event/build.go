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
// decision, deriving RiskLevel from the decision's verdict. This is the one
// standard construction path every adapter uses — see
// cli/adapter/hook.BuildActionEvent (CLI) and cli/adapter/mcp (MCP) for the
// thin per-channel wrappers around it. Centralizing this here (rather than
// duplicating risk-derivation logic per adapter) is what keeps "same risk
// mapping regardless of channel" true by construction.
func New(eventID, sessionID, actor string, channel Channel, actionType ActionType, target, raw string, d decision.Decision) ActionEvent {
	risk := RiskLow
	switch d.Verdict {
	case decision.Deny:
		risk = RiskCritical
	case decision.Prompt:
		risk = RiskHigh
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
