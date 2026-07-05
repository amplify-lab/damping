package audit

import (
	"context"
	"os"
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

// TestFollow_EmitsOnlyEventsAppendedAfterStartOffset proves the "already
// shown" boundary damping log --follow relies on: an event written before
// Follow starts, at an offset before startOffset, must never be re-emitted,
// while one appended after Follow is already running must be.
func TestFollow_EmitsOnlyEventsAppendedAfterStartOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)

	before := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	before.EventID = "evt_before"
	if err := w.Append(before); err != nil {
		t.Fatalf("append: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	startOffset := info.Size()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got := make(chan event.ActionEvent, 4)
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, startOffset, Filter{}, 5*time.Millisecond, func(e event.ActionEvent) error {
			got <- e
			return nil
		})
	}()

	after := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	after.EventID = "evt_after"
	if err := w.Append(after); err != nil {
		t.Fatalf("append: %v", err)
	}

	select {
	case e := <-got:
		if e.EventID != "evt_after" {
			t.Fatalf("expected only the post-startOffset event, got %q", e.EventID)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for Follow to emit the appended event")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Follow returned an error: %v", err)
	}
	select {
	case e := <-got:
		t.Fatalf("expected exactly one emitted event, got an unexpected extra: %+v", e)
	default:
	}
}

// TestFollow_RespectsFilter proves Follow applies f the same way ReadAll
// does, not just "everything new".
func TestFollow_RespectsFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got := make(chan event.ActionEvent, 4)
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, 0, Filter{Channel: event.ChannelMCP}, 5*time.Millisecond, func(e event.ActionEvent) error {
			got <- e
			return nil
		})
	}()

	cliEvent := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	cliEvent.EventID = "evt_cli"
	mcpEvent := sampleEvent(event.ChannelMCP, event.RiskLow, decision.Allow)
	mcpEvent.EventID = "evt_mcp"
	if err := w.Append(cliEvent); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Append(mcpEvent); err != nil {
		t.Fatalf("append: %v", err)
	}

	select {
	case e := <-got:
		if e.EventID != "evt_mcp" {
			t.Fatalf("expected only the mcp-channel event to pass the filter, got %q", e.EventID)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for Follow to emit the matching event")
	}

	cancel()
	<-done
}

// TestFollow_HandlesRotation proves Follow recovers after the file it's
// tailing is renamed away (Rotate) and a fresh, smaller file appears at the
// same path — the exact sequence a real long-running "damping log --follow"
// can observe if Rotate fires while it's running.
func TestFollow_HandlesRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)

	first := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	first.EventID = "evt_first"
	if err := w.Append(first); err != nil {
		t.Fatalf("append: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got := make(chan event.ActionEvent, 4)
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, 0, Filter{}, 5*time.Millisecond, func(e event.ActionEvent) error {
			got <- e
			return nil
		})
	}()

	// Drain the pre-existing event before simulating rotation.
	select {
	case e := <-got:
		if e.EventID != "evt_first" {
			t.Fatalf("expected evt_first, got %q", e.EventID)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for the pre-rotation event")
	}

	if _, err := Rotate(path, 1 /* bytes, force rotation */, time.Now()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	afterRotation := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	afterRotation.EventID = "evt_after_rotation"
	if err := w.Append(afterRotation); err != nil {
		t.Fatalf("append after rotation: %v", err)
	}

	select {
	case e := <-got:
		if e.EventID != "evt_after_rotation" {
			t.Fatalf("expected evt_after_rotation, got %q", e.EventID)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for Follow to recover after rotation")
	}

	cancel()
	<-done
}

func TestFollow_StopsOnContextCancel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, 0, Filter{}, 5*time.Millisecond, func(event.ActionEvent) error {
			return nil
		})
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected Follow to return nil on cancellation, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for Follow to stop after context cancellation")
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
