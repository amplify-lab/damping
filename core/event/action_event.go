// Package event defines the transport-agnostic ActionEvent schema — the single
// normalized shape every adapter (CLI hook, MCP wrapper, future HTTP proxy)
// converts its intercepted action into before it reaches core/policy or
// core/audit. See docs/architecture.md §3 for the full design rationale.
package event

import (
	"time"

	"github.com/amplify-lab/damping/core/decision"
)

// Channel identifies which transport an action arrived through.
type Channel string

const (
	ChannelCLI  Channel = "cli"
	ChannelMCP  Channel = "mcp"
	ChannelHTTP Channel = "http" // reserved, Phase 3+
)

// ActionType classifies what kind of action occurred.
type ActionType string

const (
	ActionShellExec   ActionType = "shell_exec"
	ActionToolCall    ActionType = "tool_call"
	ActionHTTPRequest ActionType = "http_request" // reserved, Phase 3+
	ActionMemoryWrite ActionType = "memory_write" // reserved, Phase 6 (Memory Guard)
	// ActionSelfDisable records a `damping off` invocation — the one
	// sanctioned way to disable enforcement (see docs/threat-model.md §4).
	// features/self_protection.feature requires this to be audited like any
	// other action, precisely because it is the most security-sensitive one.
	ActionSelfDisable ActionType = "self_disable"
)

// RiskLevel is the policy engine's risk classification for an action.
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// ActionEvent is the transport-agnostic record every adapter normalizes into.
// The field set is sized for Phase 5 compliance reports from day one — see
// docs/00-統一開發計畫（定案版）.md §五 Phase 1 step 1 and
// docs/architecture.md §3. Do not remove or repurpose fields later without a
// migration plan for existing ~/.damping/audit.jsonl files.
type ActionEvent struct {
	EventID    string            `json:"event_id"`
	Timestamp  time.Time         `json:"timestamp"`
	SessionID  string            `json:"session_id"`
	Actor      string            `json:"actor"`              // which agent/process, e.g. "claude-code", "cursor"
	Identity   string            `json:"identity,omitempty"` // empty in individual tier; populated once AD/LDAP is wired in Phase 5
	Channel    Channel           `json:"channel"`
	ActionType ActionType        `json:"action_type"`
	Target     string            `json:"target"` // path / tool name / URL
	Raw        string            `json:"raw"`    // original command / call payload, for forensics
	ParsedArgs map[string]any    `json:"parsed_args,omitempty"`
	RiskLevel  RiskLevel         `json:"risk_level"`
	Decision   decision.Decision `json:"decision"`
}

// Validate reports whether the event has the minimum fields required to be a
// meaningful, traceable audit record. It intentionally does not require
// Identity (empty is valid in the individual tier) or ParsedArgs (not every
// action has structured arguments).
func (e ActionEvent) Validate() error {
	switch {
	case e.EventID == "":
		return errRequiredField("event_id")
	case e.SessionID == "":
		return errRequiredField("session_id")
	case e.Actor == "":
		return errRequiredField("actor")
	case e.Channel == "":
		return errRequiredField("channel")
	case e.ActionType == "":
		return errRequiredField("action_type")
	case e.Decision.Verdict == "":
		return errRequiredField("decision.verdict")
	}
	return nil
}

type validationError struct{ field string }

func (e *validationError) Error() string {
	return "event: missing required field " + e.field
}

func errRequiredField(field string) error {
	return &validationError{field: field}
}
