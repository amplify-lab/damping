package audit

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

func sampleEvent(channel event.Channel, risk event.RiskLevel, verdict decision.Verdict) event.ActionEvent {
	return event.ActionEvent{
		EventID:    "evt_" + string(channel) + "_" + string(risk),
		Timestamp:  time.Now(),
		SessionID:  "sess_1",
		Actor:      "claude-code",
		Channel:    channel,
		ActionType: event.ActionShellExec,
		Target:     "rm",
		Raw:        "rm -rf ~/",
		RiskLevel:  risk,
		Decision:   decision.Decision{Verdict: verdict},
	}
}

func TestWriter_AppendAndReadAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)

	if err := w.Append(sampleEvent(event.ChannelCLI, event.RiskCritical, decision.Prompt)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Append(sampleEvent(event.ChannelMCP, event.RiskHigh, decision.Deny)); err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := ReadAll(path, Filter{})
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d", len(got))
	}
}

func TestWriter_Append_RejectsInvalidEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)
	if err := w.Append(event.ActionEvent{}); err == nil {
		t.Fatal("expected an error appending an invalid (empty) event")
	}
}

func TestReadAll_MissingFileIsEmptyNotError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.jsonl")
	got, err := ReadAll(path, Filter{})
	if err != nil {
		t.Fatalf("expected no error for a missing file, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 events, got %d", len(got))
	}
}

// TestFilter_Channel exercises the exact demonstration in
// features/mcp_tool_governance.feature: filtering by channel proves the
// cross-channel unification claim without a separate storage backend per
// channel.
func TestFilter_Channel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)
	mustAppend := func(e event.ActionEvent) {
		t.Helper()
		if err := w.Append(e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	mustAppend(sampleEvent(event.ChannelCLI, event.RiskCritical, decision.Prompt))
	mustAppend(sampleEvent(event.ChannelMCP, event.RiskHigh, decision.Deny))

	cliOnly, err := ReadAll(path, Filter{Channel: event.ChannelCLI})
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(cliOnly) != 1 || cliOnly[0].Channel != event.ChannelCLI {
		t.Fatalf("expected exactly 1 cli event, got %+v", cliOnly)
	}

	mcpOnly, err := ReadAll(path, Filter{Channel: event.ChannelMCP})
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(mcpOnly) != 1 || mcpOnly[0].Channel != event.ChannelMCP {
		t.Fatalf("expected exactly 1 mcp event, got %+v", mcpOnly)
	}
}

func TestFilter_Outcome_Degraded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)

	normal := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	degraded := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	degraded.EventID = "evt_degraded"
	degraded.Decision.Degraded = true

	if err := w.Append(normal); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Append(degraded); err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := ReadAll(path, Filter{Outcome: "degraded"})
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 1 || !got[0].Decision.Degraded {
		t.Fatalf("expected exactly 1 degraded event, got %+v", got)
	}
}

// TestPromptResolution_OneCoherentRecord exercises the audit_log.feature
// scenario "A prompt that the user resolves produces one coherent record".
func TestPromptResolution_OneCoherentRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)

	e := sampleEvent(event.ChannelCLI, event.RiskCritical, decision.Prompt)
	e.Decision.Resolve(decision.Allow)
	if err := w.Append(e); err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := ReadAll(path, Filter{})
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one record for a resolved prompt, got %d", len(got))
	}
	if got[0].Decision.Outcome() != decision.Allow {
		t.Fatalf("expected resolved outcome allow, got %v", got[0].Decision.Outcome())
	}
}

func TestRotate_RotatesWhenOverSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)
	for i := 0; i < 5; i++ {
		if err := w.Append(sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	rotated, err := Rotate(path, 10 /* bytes, force rotation */, time.Now())
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation to occur when file exceeds maxSizeBytes")
	}

	got, err := ReadAll(path, Filter{})
	if err != nil {
		t.Fatalf("ReadAll after rotate: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected the rotated-away path to read as empty, got %d events", len(got))
	}
}

func TestRotate_NoOpUnderThreshold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)
	if err := w.Append(sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)); err != nil {
		t.Fatalf("append: %v", err)
	}

	rotated, err := Rotate(path, 10*1024*1024, time.Now())
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated {
		t.Fatal("did not expect rotation under the size threshold")
	}
}
