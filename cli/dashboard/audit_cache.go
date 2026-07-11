package dashboard

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/event"
)

// readAuditAll is audit.ReadAll, reassigned as a package-level var purely so
// tests can wrap it with a call counter to observe how many times the file
// was actually re-read (see audit_cache_test.go) — production code never
// reassigns this.
var readAuditAll = audit.ReadAll

// auditSnapshot is the dashboard's shared audit-log read cache. Before this
// existed, every JSON endpoint that reads audit.jsonl (handleSummary,
// handleEvents, handleStats, handleSessions) called audit.ReadAll
// independently — a full linear rescan and JSON-decode of the whole file,
// once per endpoint, on every request (measured: the header's 15s summary
// poll, the 60s sessions/stats poll, and every filter-form keystroke each
// cost their own full-file read, even when nothing had changed since the
// last one).
//
// Keyed by (size, mtime) rather than a TTL: for a local append-only log
// those two are already exactly what distinguishes "the file changed" from
// "the file is the same," so a snapshot is reused across every request that
// lands between two real writes, and — because the rebuild itself happens
// under the same mutex a fresh read is served from — rebuilt exactly once
// per change no matter how many requests race in concurrently while it's
// stale (see load's own comment on the double-checked lock).
//
// SSE streaming (handleEventStream, POST /api/update's own output) is
// unaffected — Follow already tails the file incrementally and never goes
// through this cache.
type auditSnapshot struct {
	mu     sync.RWMutex
	loaded bool
	size   int64
	modAt  time.Time
	events []event.ActionEvent
	err    error
}

// load returns every event in path, unfiltered — callers apply their own
// audit.Filter in memory via filterEvents rather than asking for a
// pre-filtered read, so every filter combination shares the same cached
// parse instead of each triggering its own.
//
// The returned slice is the cache's own backing array, shared across
// concurrent callers — deliberately not copied defensively on every call.
// None of this package's handlers mutate it in place (filterEvents always
// builds a fresh slice for its output; handleSessions, the one caller that
// takes the unfiltered result directly, only ever reads it), so sharing it
// costs no more memory than a single request already held transiently
// before this cache existed.
func (c *auditSnapshot) load(path string) ([]event.ActionEvent, error) {
	info, statErr := os.Stat(path)
	if statErr != nil && !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("audit: stat %s: %w", path, statErr)
	}
	exists := statErr == nil
	var size int64
	var modAt time.Time
	if exists {
		size = info.Size()
		modAt = info.ModTime()
	}

	c.mu.RLock()
	fresh := c.loaded && exists && c.size == size && c.modAt.Equal(modAt)
	events, err := c.events, c.err
	c.mu.RUnlock()
	if fresh {
		return events, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check under the write lock: another request may have already
	// rebuilt the snapshot for this exact (size, mtime) while this one was
	// blocked waiting for the lock. This double-checked pattern is what
	// makes a rebuild single-flight on a change — the mutex itself
	// serializes it, no separate in-flight flag needed.
	if c.loaded && exists && c.size == size && c.modAt.Equal(modAt) {
		return c.events, c.err
	}

	c.events, c.err = readAuditAll(path, audit.Filter{})
	c.size, c.modAt, c.loaded = size, modAt, true
	return c.events, c.err
}

// auditEvents returns every event currently in the audit log, unfiltered,
// through s.auditCache — the shared read path handleSummary, handleEvents,
// handleStats, and handleSessions all now use instead of each calling
// audit.ReadAll on their own.
func (s *Server) auditEvents() ([]event.ActionEvent, error) {
	return s.auditCache.load(s.cfg.AuditPath)
}

// filterEvents applies f in memory over an already-loaded event slice —
// equivalent to audit.ReadAll(path, f), since ReadAll's own filtering is
// just Filter.Matches applied per record as it's decoded, but without
// re-reading or re-decoding the file for a filter combination the cache
// already has parsed.
func filterEvents(events []event.ActionEvent, f audit.Filter) []event.ActionEvent {
	out := make([]event.ActionEvent, 0, len(events))
	for _, e := range events {
		if f.Matches(e) {
			out = append(out, e)
		}
	}
	return out
}
