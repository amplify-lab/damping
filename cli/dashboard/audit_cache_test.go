package dashboard

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/amplify-lab/damping/cli/policies"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

// withCountingReadAuditAll wraps the package-level readAuditAll (the seam
// auditSnapshot.load calls through) with a call counter, restored via
// t.Cleanup — the honest way to observe "how many times was the file
// actually re-read" without depending on timing or a fake filesystem.
func withCountingReadAuditAll(t *testing.T) *int32 {
	t.Helper()
	var n int32
	orig := readAuditAll
	readAuditAll = func(path string, f audit.Filter) ([]event.ActionEvent, error) {
		atomic.AddInt32(&n, 1)
		return orig(path, f)
	}
	t.Cleanup(func() { readAuditAll = orig })
	return &n
}

func TestAuditSnapshot_ReusesCacheWhenFileUnchanged(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	if err := w.Append(sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})); err != nil {
		t.Fatalf("append: %v", err)
	}
	n := withCountingReadAuditAll(t)

	events1, err := s.auditEvents()
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	events2, err := s.auditEvents()
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if len(events1) != 1 || len(events2) != 1 {
		t.Fatalf("expected 1 event both times, got %d and %d", len(events1), len(events2))
	}
	if got := atomic.LoadInt32(n); got != 1 {
		t.Fatalf("expected exactly 1 underlying read across 2 requests against an unchanged file, got %d", got)
	}
}

// TestAuditSnapshot_RebuildsWhenFileChanges is the change-invalidates
// counterpart: an append between two reads must produce a fresh underlying
// read, not a stale cached one — the file's size changes on every append
// regardless of the host filesystem's mtime resolution, which is what the
// cache actually keys its freshness check on alongside mtime.
func TestAuditSnapshot_RebuildsWhenFileChanges(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	if err := w.Append(sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})); err != nil {
		t.Fatalf("append: %v", err)
	}
	n := withCountingReadAuditAll(t)

	if _, err := s.auditEvents(); err != nil {
		t.Fatalf("first load: %v", err)
	}
	if err := w.Append(sampleEvent("s2", "claude-code", event.ChannelCLI, event.RiskHigh, decision.Decision{Verdict: decision.Deny})); err != nil {
		t.Fatalf("append: %v", err)
	}
	events, err := s.auditEvents()
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events after the second append, got %d", len(events))
	}
	if got := atomic.LoadInt32(n); got != 2 {
		t.Fatalf("expected a fresh underlying read once the file changed, got %d total reads", got)
	}
}

// TestAuditSnapshot_ConcurrentRequestsSingleFlightOneRebuild confirms a
// rebuild is single-flight: many concurrent callers hitting an unchanged
// file must never each independently re-read it, they must all converge on
// the one snapshot the mutex's double-checked lock in auditSnapshot.load
// produces. Deterministic (not timing-dependent): the write-lock re-check
// guarantees exactly one caller ever reaches readAuditAll for a given
// (size, mtime), regardless of scheduling.
func TestAuditSnapshot_ConcurrentRequestsSingleFlightOneRebuild(t *testing.T) {
	s, auditPath := newTestServer(t, policies.Default)
	w := audit.NewWriter(auditPath)
	if err := w.Append(sampleEvent("s1", "claude-code", event.ChannelCLI, event.RiskLow, decision.Decision{Verdict: decision.Allow})); err != nil {
		t.Fatalf("append: %v", err)
	}
	n := withCountingReadAuditAll(t)

	const concurrency = 20
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			if _, err := s.auditEvents(); err != nil {
				t.Errorf("concurrent load: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(n); got != 1 {
		t.Fatalf("expected exactly 1 underlying read across %d concurrent requests against an unchanged file, got %d", concurrency, got)
	}
}
