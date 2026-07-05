package event

import (
	"testing"
	"time"

	"github.com/amplify-lab/damping/core/decision"
)

func validEvent() ActionEvent {
	return ActionEvent{
		EventID:    "evt_1",
		Timestamp:  time.Now(),
		SessionID:  "sess_1",
		Actor:      "claude-code",
		Channel:    ChannelCLI,
		ActionType: ActionShellExec,
		Target:     "rm",
		Raw:        "rm -rf ~/",
		RiskLevel:  RiskCritical,
		Decision:   decision.Decision{Verdict: decision.Prompt},
	}
}

func TestActionEvent_Validate_OK(t *testing.T) {
	e := validEvent()
	if err := e.Validate(); err != nil {
		t.Fatalf("expected valid event, got error: %v", err)
	}
}

func TestActionEvent_Validate_EmptyIdentityIsFine(t *testing.T) {
	e := validEvent()
	e.Identity = ""
	if err := e.Validate(); err != nil {
		t.Fatalf("empty identity must be valid in the individual tier, got: %v", err)
	}
}

func TestActionEvent_Validate_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ActionEvent)
	}{
		{"event_id", func(e *ActionEvent) { e.EventID = "" }},
		{"session_id", func(e *ActionEvent) { e.SessionID = "" }},
		{"actor", func(e *ActionEvent) { e.Actor = "" }},
		{"channel", func(e *ActionEvent) { e.Channel = "" }},
		{"action_type", func(e *ActionEvent) { e.ActionType = "" }},
		{"decision.verdict", func(e *ActionEvent) { e.Decision = decision.Decision{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEvent()
			tc.mutate(&e)
			if err := e.Validate(); err == nil {
				t.Fatalf("expected validation error when %s is missing", tc.name)
			}
		})
	}
}

func TestActionEvent_Decision_Outcome(t *testing.T) {
	e := validEvent()
	if got := e.Decision.Outcome(); got != decision.Prompt {
		t.Fatalf("expected outcome %q before resolution, got %q", decision.Prompt, got)
	}

	e.Decision.Resolve(decision.Allow)
	if got := e.Decision.Outcome(); got != decision.Allow {
		t.Fatalf("expected resolved outcome %q, got %q", decision.Allow, got)
	}
}
