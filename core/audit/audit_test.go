package audit

import (
	"context"
	"errors"
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

// TestReadAll_TolerantOfTornTrailingWrite is a regression test found via
// adversarial review: Writer.Append is not the only thing that can leave a
// non-newline-terminated final line on disk — a process killed mid-write
// does too, and this must not be confused with real corruption. Before
// this fix, ReadAll used bufio.Scanner, which returns a final unterminated
// fragment as an ordinary complete token — so any unclean kill during the
// very last Append permanently broke every future `damping log` call on
// that file (ReadAll would hit the same truncated "line" every time and
// return zero events, not just omit the incomplete one).
func TestReadAll_TolerantOfTornTrailingWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)
	if err := w.Append(sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)); err != nil {
		t.Fatalf("append: %v", err)
	}

	// Simulate a write killed partway through: valid complete JSON with no
	// trailing newline, appended directly (bypassing Writer.Append, which
	// always writes the newline in the same call).
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("opening for torn write simulation: %v", err)
	}
	if _, err := f.Write([]byte(`{"event_id":"evt_torn","session_id":"s1","actor":"x","channel":"cli"`)); err != nil {
		t.Fatalf("writing torn line: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	got, err := ReadAll(path, Filter{})
	if err != nil {
		t.Fatalf("expected a torn trailing write to be tolerated, not treated as an error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly the 1 complete record (torn trailing line ignored), got %d", len(got))
	}
}

// TestReadAll_StillErrorsOnGenuineMidFileCorruption proves the fix above
// doesn't overcorrect: a malformed line that *does* have its terminating
// newline (so it can't be an in-flight write) is real corruption and must
// still surface as an error, exactly as before.
func TestReadAll_StillErrorsOnGenuineMidFileCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)
	if err := w.Append(sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)); err != nil {
		t.Fatalf("append: %v", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("opening to inject corruption: %v", err)
	}
	if _, err := f.Write([]byte("not valid json at all\n")); err != nil {
		t.Fatalf("writing corrupt line: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	if _, err := ReadAll(path, Filter{}); err == nil {
		t.Fatal("expected an error for a genuinely malformed, newline-terminated record")
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

// TestParseFilter_BuildsEquivalentFilter is a regression test for the
// extraction of this logic out of cli/cmd/log.go's buildLogFilter — moved
// here so the local dashboard's HTTP handlers can parse the identical
// vocabulary (?channel=, ?risk=, etc.) without importing the cmd package.
func TestParseFilter_BuildsEquivalentFilter(t *testing.T) {
	f, err := ParseFilter("cli", "high", "claude-code", "deny", "24h")
	if err != nil {
		t.Fatalf("ParseFilter: %v", err)
	}
	if f.Channel != event.ChannelCLI || f.Risk != event.RiskHigh || f.Actor != "claude-code" || f.Outcome != "deny" {
		t.Fatalf("expected fields to pass through unchanged, got %+v", f)
	}
	if f.Since.IsZero() || time.Since(f.Since) < 23*time.Hour || time.Since(f.Since) > 25*time.Hour {
		t.Fatalf("expected Since to resolve to ~24h ago, got %v", f.Since)
	}
}

func TestParseFilter_EmptySinceLeavesZeroTime(t *testing.T) {
	f, err := ParseFilter("", "", "", "", "")
	if err != nil {
		t.Fatalf("ParseFilter: %v", err)
	}
	if !f.Since.IsZero() {
		t.Fatalf("expected a zero Since when since is unset, got %v", f.Since)
	}
}

func TestParseFilter_InvalidSinceErrors(t *testing.T) {
	if _, err := ParseFilter("", "", "", "", "not-a-duration"); err == nil {
		t.Fatal("expected an error for an unparseable since duration")
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

// TestFollow_PropagatesCallbackError is a coverage gap found via
// adversarial review: Follow's own doc comment claims fn returning an
// error "stops the tail immediately," but nothing exercised that path.
func TestFollow_PropagatesCallbackError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)
	if err := w.Append(sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)); err != nil {
		t.Fatalf("append: %v", err)
	}

	wantErr := errors.New("boom")
	err := Follow(context.Background(), path, 0, Filter{}, 5*time.Millisecond, func(event.ActionEvent) error {
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected Follow to propagate fn's error, got %v", err)
	}
}

// TestFollow_ErrorsOnGenuineCorruptionInFollowedPortion is the Follow-side
// counterpart to TestReadAll_StillErrorsOnGenuineMidFileCorruption: a
// malformed but newline-terminated line appended *after* Follow starts must
// still surface as an error (it can't be an in-flight write, since it has
// its terminating newline), not be silently swallowed.
func TestFollow_ErrorsOnGenuineCorruptionInFollowedPortion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)
	if err := w.Append(sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)); err != nil {
		t.Fatalf("append: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, 0, Filter{}, 5*time.Millisecond, func(event.ActionEvent) error {
			return nil
		})
	}()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("opening to inject corruption: %v", err)
	}
	if _, err := f.Write([]byte("not valid json at all\n")); err != nil {
		t.Fatalf("writing corrupt line: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected Follow to return an error for a genuinely malformed followed record")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for Follow to notice the corrupt line")
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
