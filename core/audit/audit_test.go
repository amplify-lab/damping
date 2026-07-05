package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// TestWriter_Append_TruncatesOversizedRawField is a regression test/
// hardening measure: followFrom's doc comment relies on Append emitting
// one JSON line via a *single* os.File.Write call to guarantee a partial
// write can only ever be missing bytes from the end of the line — but
// that's a Go-runtime guarantee that only holds up to ~1 GiB per Write
// call (internal/poll splits anything larger into multiple write(2)
// syscalls), and ActionEvent.Raw is otherwise unbounded, sourced verbatim
// from arbitrary CLI/MCP payloads. Append must cap it well below that
// threshold rather than relying on no legitimate command ever being that
// large.
func TestWriter_Append_TruncatesOversizedRawField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)

	e := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	e.Raw = strings.Repeat("a", maxRawFieldSize*2)
	if err := w.Append(e); err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := ReadAll(path, Filter{})
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 event, got %d", len(got))
	}
	if len(got[0].Raw) > maxRawFieldSize {
		t.Fatalf("expected Raw to be capped at %d bytes, got %d", maxRawFieldSize, len(got[0].Raw))
	}
	if !strings.HasSuffix(got[0].Raw, "[truncated]") {
		t.Fatalf("expected the truncated Raw to end with a visible marker, got suffix: %q", got[0].Raw[len(got[0].Raw)-20:])
	}
}

// TestWriter_Append_DoesNotTruncateRawUnderTheCap is the false-positive
// guard: a realistic, sizable-but-legitimate command must survive intact.
func TestWriter_Append_DoesNotTruncateRawUnderTheCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)

	e := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	e.Raw = "echo " + strings.Repeat("a", 10_000)
	if err := w.Append(e); err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := ReadAll(path, Filter{})
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 1 || got[0].Raw != e.Raw {
		t.Fatalf("expected the realistic-sized Raw to survive unchanged, got length %d (want %d)", len(got[0].Raw), len(e.Raw))
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

func TestLimitMostRecent_KeepsLastN(t *testing.T) {
	events := make([]event.ActionEvent, 5)
	for i := range events {
		events[i] = sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
		events[i].EventID = string(rune('a' + i))
	}
	got := LimitMostRecent(events, 2)
	if len(got) != 2 || got[0].EventID != "d" || got[1].EventID != "e" {
		t.Fatalf("expected the last 2 events (d, e), got %+v", got)
	}
}

func TestLimitMostRecent_ZeroOrNegativeMeansUnlimited(t *testing.T) {
	events := make([]event.ActionEvent, 3)
	if got := LimitMostRecent(events, 0); len(got) != 3 {
		t.Fatalf("expected limit 0 to mean unlimited, got %d events", len(got))
	}
	if got := LimitMostRecent(events, -1); len(got) != 3 {
		t.Fatalf("expected a negative limit to mean unlimited, got %d events", len(got))
	}
}

func TestLimitMostRecent_LimitLargerThanLengthIsNoOp(t *testing.T) {
	events := make([]event.ActionEvent, 3)
	if got := LimitMostRecent(events, 10); len(got) != 3 {
		t.Fatalf("expected no truncation when limit exceeds length, got %d events", len(got))
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

// TestRotate_TwoRotationsInSameSecondDoNotCollide is a regression test for
// a real data-loss bug: the rotated filename only had second-level
// resolution, so a second Rotate call within the same wall-clock second
// (entirely plausible once Append triggers rotation on every write that
// crosses the threshold, not just as a rare manual operation) computed the
// exact same target filename as the first — and os.Rename silently
// replaces an existing destination, so the second rotation would overwrite
// the first rotated file, permanently losing whatever it held.
func TestRotate_TwoRotationsInSameSecondDoNotCollide(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	now := time.Now()

	w1 := NewWriter(path)
	first := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	first.EventID = "evt_generation_1"
	if err := w1.Append(first); err != nil {
		t.Fatalf("append: %v", err)
	}
	rotated1, err := Rotate(path, 1 /* bytes, force rotation */, now)
	if err != nil {
		t.Fatalf("first Rotate: %v", err)
	}
	if !rotated1 {
		t.Fatal("expected the first rotation to occur")
	}

	w2 := NewWriter(path)
	second := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	second.EventID = "evt_generation_2"
	if err := w2.Append(second); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Same `now` as the first Rotate call — simulates two rotations
	// completing within the same wall-clock second.
	rotated2, err := Rotate(path, 1 /* bytes, force rotation */, now)
	if err != nil {
		t.Fatalf("second Rotate: %v", err)
	}
	if !rotated2 {
		t.Fatal("expected the second rotation to occur")
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Name() == "audit.jsonl" || !strings.HasPrefix(e.Name(), "audit.jsonl.") {
			continue
		}
		got, err := ReadAll(filepath.Join(filepath.Dir(path), e.Name()), Filter{})
		if err != nil {
			t.Fatalf("ReadAll(%s): %v", e.Name(), err)
		}
		for _, ev := range got {
			seen[ev.EventID] = true
		}
	}
	if !seen["evt_generation_1"] {
		t.Fatal("evt_generation_1 was lost — the second same-second rotation silently overwrote the first rotated file")
	}
	if !seen["evt_generation_2"] {
		t.Fatal("evt_generation_2 was lost")
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

	startInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got := make(chan event.ActionEvent, 4)
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, startInfo, Filter{}, 5*time.Millisecond, func(e event.ActionEvent) error {
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
		done <- Follow(ctx, path, nil, Filter{Channel: event.ChannelMCP}, 5*time.Millisecond, func(e event.ActionEvent) error {
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
		done <- Follow(ctx, path, nil, Filter{}, 5*time.Millisecond, func(e event.ActionEvent) error {
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

// TestFollow_DetectsRotationThatCompletedBeforeItStarted is a regression
// test for a real bug: Follow used to take a bare startOffset int64, always
// initializing its internal lastInfo to nil — so a rotation that already
// completed in the window between the caller's own pre-Follow os.Stat and
// Follow's first internal check could never be detected by file identity
// at all on that first check, only by the much weaker size-shrink
// fallback, which doesn't help when the new file has already regrown past
// the old offset by the time anyone looks. Reproduces that exact window: a
// baseline is stat'd, the file is then rotated away and refilled with
// unrelated, larger content *before* Follow is ever called, and Follow must
// still recognize the identity change (via the caller-supplied startInfo)
// rather than seeking into the new file at the stale offset.
func TestFollow_DetectsRotationThatCompletedBeforeItStarted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w := NewWriter(path)

	baseline := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	baseline.EventID = "evt_baseline"
	if err := w.Append(baseline); err != nil {
		t.Fatalf("append: %v", err)
	}

	// The caller's own pre-Follow stat — this is what log.go/handlers.go
	// capture before ever calling Follow.
	startInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// Simulate a rotation completing in the window between that stat and
	// Follow actually starting: rename the file away, then write a fresh
	// file at the same path containing unrelated events whose total size
	// already exceeds startInfo's size — the exact condition under which
	// the old size-shrink fallback could never fire either.
	if err := os.Rename(path, path+".rotated"); err != nil {
		t.Fatalf("simulating rotation: %v", err)
	}
	w2 := NewWriter(path)
	newGenEvent1 := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	newGenEvent1.EventID = "evt_new_gen_1"
	newGenEvent2 := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
	newGenEvent2.EventID = "evt_new_gen_2"
	if err := w2.Append(newGenEvent1); err != nil {
		t.Fatalf("append to new generation: %v", err)
	}
	if err := w2.Append(newGenEvent2); err != nil {
		t.Fatalf("append to new generation: %v", err)
	}
	if info, statErr := os.Stat(path); statErr != nil || info.Size() <= startInfo.Size() {
		t.Fatalf("test setup invariant violated: new generation must be larger than the old offset (old=%d)", startInfo.Size())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	got := make(chan event.ActionEvent, 4)
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, startInfo, Filter{}, 5*time.Millisecond, func(e event.ActionEvent) error {
			got <- e
			return nil
		})
	}()

	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case e := <-got:
			seen[e.EventID] = true
		case <-time.After(1 * time.Second):
			t.Fatalf("timed out waiting for the new generation's events; got so far: %v", seen)
		}
	}
	if !seen["evt_new_gen_1"] || !seen["evt_new_gen_2"] {
		t.Fatalf("expected both new-generation events to be read from the top of the new file, got %v", seen)
	}
	if seen["evt_baseline"] {
		t.Fatal("did not expect the old generation's baseline event to be re-emitted")
	}

	cancel()
	<-done
}

func TestFollow_StopsOnContextCancel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, nil, Filter{}, 5*time.Millisecond, func(event.ActionEvent) error {
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
	err := Follow(context.Background(), path, nil, Filter{}, 5*time.Millisecond, func(event.ActionEvent) error {
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
		done <- Follow(ctx, path, nil, Filter{}, 5*time.Millisecond, func(event.ActionEvent) error {
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

// TestWriterAppend_RotatesWhenOverThreshold is a regression test for a real
// gap: docs/00-統一開發計畫（定案版）.md requires basic file rotation so the
// audit log doesn't grow unbounded, and Rotate itself was fully implemented
// and unit-tested — but nothing in the whole program ever called it, so in
// real usage the file grew forever. Append must now trigger rotation itself
// once the file crosses maxAuditFileSize, with no separate caller needed.
func TestWriterAppend_RotatesWhenOverThreshold(t *testing.T) {
	orig := maxAuditFileSize
	maxAuditFileSize = 500 // small enough that a handful of sample events cross it
	t.Cleanup(func() { maxAuditFileSize = orig })

	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w := NewWriter(path)

	const n = 10
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		e := sampleEvent(event.ChannelCLI, event.RiskLow, decision.Allow)
		e.EventID = fmt.Sprintf("evt_%d", i)
		ids[i] = e.EventID
		if err := w.Append(e); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rotatedSiblingFound bool
	for _, e := range entries {
		if e.Name() != "audit.jsonl" && strings.HasPrefix(e.Name(), "audit.jsonl.") {
			rotatedSiblingFound = true
		}
	}
	if !rotatedSiblingFound {
		t.Fatalf("expected at least one rotated sibling file after writing enough events to repeatedly cross the threshold, got entries: %v", entries)
	}

	// No data lost across rotation: every event written must still be
	// readable from *somewhere* — either the live file or a rotated
	// sibling. ReadAll only ever reads one path, so union across every
	// audit-log-shaped file in the directory.
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Name() != "audit.jsonl" && !strings.HasPrefix(e.Name(), "audit.jsonl.") {
			continue
		}
		got, err := ReadAll(filepath.Join(dir, e.Name()), Filter{})
		if err != nil {
			t.Fatalf("ReadAll(%s): %v", e.Name(), err)
		}
		for _, ev := range got {
			seen[ev.EventID] = true
		}
	}
	for _, id := range ids {
		if !seen[id] {
			t.Fatalf("expected event %q to be readable from some generation, but it's missing entirely (data loss across rotation)", id)
		}
	}
}
