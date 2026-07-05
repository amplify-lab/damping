// Package audit is the single write path for ~/.damping/audit.jsonl.
// core/audit is the only component that appends to the audit log — CLI and
// MCP adapters normalize their intercepted actions into an event.ActionEvent
// and hand it here; they never write the file themselves. This is the
// concrete enforcement of the "single audit outlet" rule in
// docs/00-統一開發計畫（定案版）.md and features/audit_log.feature.
package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/amplify-lab/damping/core/event"
)

// Writer appends ActionEvents to a JSONL file, one JSON object per line.
type Writer struct {
	path string
	mu   sync.Mutex
}

// NewWriter creates a Writer for the given path, creating parent directories
// if needed. It does not open the file until the first Append call.
func NewWriter(path string) *Writer {
	return &Writer{path: path}
}

// maxAuditFileSize is the size threshold at which Append rotates the audit
// file to a timestamped sibling before returning — see Rotate's own doc
// comment for why V1 keeps this simple (single-generation, no retention/
// compression/count-limit policy). Checked after every successful write
// rather than on a separate timer or background goroutine, since Append is
// the only place the file's size ever changes and so the only place that
// needs to ask. Found via review: docs/00-統一開發計畫（定案版）.md §五
// requires "basic file rotation ... to avoid growing without bound," and
// Rotate itself was fully implemented and unit-tested, but nothing
// anywhere in the program ever called it — the audit log grew forever in
// real usage. ~10 MiB comfortably holds tens of thousands of typical JSONL
// records, far more history than an individual developer's local audit
// log realistically needs before starting a fresh generation is fine. A
// package-level var, not a const, so tests can shrink it instead of
// writing megabytes of fixture data — the same pattern cli/cmd/log.go's
// logFollowPollInterval uses for the identical reason.
var maxAuditFileSize int64 = 10 * 1024 * 1024

// Append validates and writes one ActionEvent as a single JSON line. The
// named return lets the deferred Close below surface a late write failure
// (e.g. a full disk or quota error that only manifests when buffered data
// is actually flushed) instead of silently discarding it — found via
// golangci-lint's errcheck: for a security audit log, "the write appeared
// to succeed but the bytes never reached disk" is exactly the kind of
// silent failure this project's own philosophy (docs/threat-model.md §6)
// says must never happen.
func (w *Writer) Append(e event.ActionEvent) (err error) {
	if verr := e.Validate(); verr != nil {
		return fmt.Errorf("audit: refusing to write invalid event: %w", verr)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if merr := os.MkdirAll(filepath.Dir(w.path), 0o700); merr != nil {
		return fmt.Errorf("audit: creating audit directory: %w", merr)
	}
	f, operr := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if operr != nil {
		return fmt.Errorf("audit: opening %s: %w", w.path, operr)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("audit: closing %s: %w", w.path, cerr)
		}
	}()

	line, merr := json.Marshal(e)
	if merr != nil {
		return fmt.Errorf("audit: encoding event: %w", merr)
	}
	if _, werr := f.Write(append(line, '\n')); werr != nil {
		return fmt.Errorf("audit: writing event: %w", werr)
	}

	// The event above is already durably appended by this point — a
	// rotation failure here is a housekeeping problem, not a lost record,
	// so the wrapped error says so explicitly rather than reading like a
	// generic "the write failed" to a caller that only logs err.Error().
	if _, rerr := Rotate(w.path, maxAuditFileSize, time.Now()); rerr != nil {
		return fmt.Errorf("audit: event appended, but rotating the file afterward failed: %w", rerr)
	}
	return nil
}

// Filter narrows ReadAll results. A zero-value field means "don't filter on
// this dimension" — see docs/cli-reference.md §7 for the CLI flags this maps
// to (--channel, --risk, --actor, --since, --outcome).
type Filter struct {
	Channel event.Channel
	Risk    event.RiskLevel
	Actor   string
	Since   time.Time
	Outcome string // matches event.Verdict values, or "degraded"
}

// Matches reports whether e satisfies every non-zero field of f.
func (f Filter) Matches(e event.ActionEvent) bool {
	if f.Channel != "" && e.Channel != f.Channel {
		return false
	}
	if f.Risk != "" && e.RiskLevel != f.Risk {
		return false
	}
	if f.Actor != "" && e.Actor != f.Actor {
		return false
	}
	if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
		return false
	}
	if f.Outcome != "" {
		if f.Outcome == "degraded" {
			if !e.Decision.Degraded {
				return false
			}
		} else if string(e.Decision.Outcome()) != f.Outcome {
			return false
		}
	}
	return true
}

// ParseFilter builds a Filter from the same string vocabulary every surface
// that filters the audit log accepts — `damping log`'s flags and the local
// dashboard's query parameters both parse through this one implementation,
// per docs/ux-dashboard-spec.md §4's "CLI/dashboard vocabulary parity"
// principle: there is exactly one place that decides what "--risk high" or
// "?risk=high" means. since, if non-empty, is a Go duration string (e.g.
// "24h") measured back from now; an empty since leaves Filter.Since zero
// (matches everything).
func ParseFilter(channel, risk, actor, outcome, since string) (Filter, error) {
	f := Filter{
		Channel: event.Channel(channel),
		Risk:    event.RiskLevel(risk),
		Actor:   actor,
		Outcome: outcome,
	}
	if since != "" {
		d, err := time.ParseDuration(since)
		if err != nil {
			return Filter{}, err
		}
		f.Since = time.Now().Add(-d)
	}
	return f, nil
}

// LimitMostRecent keeps only the last n of events (assumed already in
// chronological order, as ReadAll returns them), discarding older ones —
// the shared "--limit"/"?limit=" truncation both `damping log` and the
// local dashboard's `/api/events` apply after filtering, for the same
// vocabulary-parity reason ParseFilter exists. n <= 0 means unlimited,
// matching `damping log --limit 0`'s existing meaning.
func LimitMostRecent(events []event.ActionEvent, n int) []event.ActionEvent {
	if n > 0 && len(events) > n {
		return events[len(events)-n:]
	}
	return events
}

// ReadAll reads every ActionEvent from path and returns those matching f. A
// missing file is treated as an empty log, not an error — a brand new
// install with no interceptions yet is a normal state, not a failure.
//
// Implemented via followFrom (starting at offset 0) rather than its own
// scan, so a torn trailing write (Writer.Append killed mid-write, e.g. the
// process was interrupted while writing the very last record) is tolerated
// exactly the same way here as it is mid-tail in Follow — see followFrom's
// doc comment for why that specific case is not corruption. Found via
// adversarial review: the previous bufio.Scanner-based version had no way
// to distinguish "a genuinely malformed complete line" from "an in-flight
// write that hadn't finished yet," so any unclean kill during the last
// Append permanently broke every future `damping log` call on that file —
// worse than merely showing a stale record, since every read of the whole
// file failed, not just the incomplete tail.
func ReadAll(path string, f Filter) ([]event.ActionEvent, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("audit: stat %s: %w", path, err)
	}

	var out []event.ActionEvent
	_, err := followFrom(path, 0, f, func(e event.ActionEvent) error {
		out = append(out, e)
		return nil
	})
	return out, err
}

// Follow tails path starting from startInfo — the os.FileInfo the caller
// observed right before calling Follow, typically right after finishing an
// initial ReadAll (see `damping log --follow` in cli/cmd/log.go), or nil if
// the file didn't exist at that point. Only appends after startInfo's size
// are delivered. Follow calls fn for each new ActionEvent matching f as
// it's appended, and blocks until ctx is cancelled, returning nil, or fn
// returns an error, which stops the tail immediately.
//
// Follow polls rather than using a filesystem-event API (inotify/kqueue/
// ReadDirectoryChangesW) to stay dependency-free and portable across every
// platform Damping ships on; pollInterval trades responsiveness against
// wakeups. Rotate renaming the file away and a fresh file appearing at the
// same path is treated as "start over from the top of the current file" —
// detected via file identity (os.SameFile), not just a size check, since
// the new file isn't guaranteed to be smaller than the old offset (a later
// event's JSON encoding can easily be longer than an earlier one's).
// startInfo is required (rather than a bare startOffset int64, an earlier
// version's signature) specifically so this identity check has something
// real to compare against from Follow's very first check — an earlier
// version always started with a nil lastInfo, so a rotation completing
// between the caller's own pre-Follow stat and Follow's first internal one
// could never be detected by identity at all, only by the weaker
// size-shrink fallback (which itself only helps if the poll happens to land
// while the file is still smaller than the old offset). The first content
// check now also runs immediately, before the first pollInterval tick,
// narrowing that window further rather than always waiting one full
// interval before ever looking.
//
// Known, disclosed limitation: this only detects rotation, it doesn't make
// polling omniscient. A same-inode truncate-in-place rotation (e.g. an
// external tool's logrotate `copytruncate` policy, as opposed to Damping's
// own rename-based Rotate) keeps os.SameFile reporting "same file," so if
// it also regrows past the old offset before the very next check, neither
// the identity check nor the size-shrink fallback fires, and Follow
// misreads the regrown content at the stale offset. Likewise, if the file
// at path is replaced more than once between two consecutive checks (e.g.
// two rotations firing faster than pollInterval), the generation that
// existed only in between is already gone by the time Follow looks and can
// never be read at all — an inherent limit of polling a path rather than
// subscribing to filesystem events, not something a smarter offset/identity
// comparison can fix. Neither case applies to Damping's own Rotate, which
// is rename-based and fires at most once per Append call.
func Follow(ctx context.Context, path string, startInfo os.FileInfo, f Filter, pollInterval time.Duration, fn func(event.ActionEvent) error) error {
	var offset int64
	if startInfo != nil {
		offset = startInfo.Size()
	}
	lastInfo := startInfo
	fileWasMissing := false

	check := func() error {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			// The file may reappear at this path (Rotate renames it away,
			// the next Append recreates it fresh) — remember that we've
			// lost track of it so whatever shows up next is read from the
			// top, never seeked into using a now-meaningless offset.
			lastInfo = nil
			fileWasMissing = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("audit: stat %s: %w", path, err)
		}

		switch {
		case fileWasMissing:
			offset = 0 // it just reappeared — everything in it now is new to us
		case lastInfo != nil && !os.SameFile(lastInfo, info):
			offset = 0 // a different file now lives at this path (e.g. Rotate)
		case info.Size() < offset:
			offset = 0 // same file but shrank somehow — start over defensively
		}
		fileWasMissing = false
		lastInfo = info

		if info.Size() == offset {
			return nil // nothing new this check
		}

		newOffset, err := followFrom(path, offset, f, fn)
		if err != nil {
			return err
		}
		offset = newOffset
		return nil
	}

	if err := check(); err != nil {
		return err
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if err := check(); err != nil {
			return err
		}
	}
}

// followFrom reads only complete (newline-terminated) records appended
// after offset, calling fn for each one matching f and returning the offset
// just past the last complete record it consumed (never past a trailing
// partial line). Writer.Append writes one full JSON line plus '\n' in a
// single Write call, so a partial write can only ever be missing bytes
// from the *end* of that line, including the newline itself — it can never
// produce a scrambled line with a premature newline in the middle. A
// trailing line with no newline is therefore always an in-flight write
// that simply hasn't finished yet, never corruption, so it's left unread
// for the next poll rather than risking a spurious "malformed record"
// error on a write that's still happening. A line that *does* have its
// terminating newline but still fails to parse is genuine corruption
// (or a bug in whatever wrote it) and is still reported as an error — that
// distinction is exactly what a plain bufio.Scanner-based line reader can't
// make, since ScanLines returns a final unterminated fragment as an
// ordinary complete token indistinguishable from a real one.
//
// This assumes an os.OpenFile(O_APPEND) write of one JSONL record is
// effectively atomic from a concurrent reader's perspective, which holds in
// practice on a local Linux/macOS filesystem (single-inode write ordering)
// but is not a portable guarantee — notably, O_APPEND is documented as
// non-atomic over NFS. A ~/.damping directory on an NFS mount is out of
// scope for V1; this is a known, narrow limitation, not something this
// function tries to defend against.
func followFrom(path string, offset int64, f Filter, fn func(event.ActionEvent) error) (int64, error) {
	file, err := os.Open(path) // #nosec G304 -- path is the local user's own audit log (~/.damping default), not an attacker-influenced path; no cross-trust-boundary traversal risk
	if err != nil {
		return offset, fmt.Errorf("audit: opening %s: %w", path, err)
	}
	// A Close error on a read-only descriptor carries no data-loss risk
	// (nothing buffered to flush) — deliberately, not accidentally, ignored.
	defer func() { _ = file.Close() }()

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return offset, fmt.Errorf("audit: seeking %s: %w", path, err)
	}

	pos := offset
	lineNo := 0
	reader := bufio.NewReaderSize(file, 64*1024)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			lineNo++
			pos += int64(len(line))
			if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
				var e event.ActionEvent
				if err := json.Unmarshal(trimmed, &e); err != nil {
					return pos, fmt.Errorf("audit: %s: malformed record at line %d past offset %d: %w", path, lineNo, offset, err)
				}
				if f.Matches(e) {
					if err := fn(e); err != nil {
						return pos, err
					}
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return pos, nil
			}
			return pos, fmt.Errorf("audit: reading %s: %w", path, readErr)
		}
	}
}

// Rotate renames the audit file to a timestamped sibling once it exceeds
// maxSizeBytes, then lets the next Append start a fresh file. Single-
// generation rotation is intentionally simple for V1 — see
// docs/00-統一開發計畫（定案版）.md §五 Phase 1 step 7, log rotation is
// flagged as needed but not over-engineered before real usage patterns
// exist.
func Rotate(path string, maxSizeBytes int64, now time.Time) (rotated bool, err error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("audit: stat %s: %w", path, err)
	}
	if info.Size() < maxSizeBytes {
		return false, nil
	}
	rotatedPath, err := uniqueRotatedPath(path, now)
	if err != nil {
		return false, err
	}
	if err := os.Rename(path, rotatedPath); err != nil {
		return false, fmt.Errorf("audit: rotating %s: %w", path, err)
	}
	return true, nil
}

// uniqueRotatedPath finds a rotated-sibling filename for path that doesn't
// already exist, appending a numeric suffix if the plain timestamped name
// (second-resolution) collides with one already on disk. Found via review,
// once Rotate started being called from every Append that crosses the
// threshold rather than only as a rare manual/administrative operation: two
// rotations within the same wall-clock second are entirely plausible under
// a burst of intercepted commands, and os.Rename silently replaces an
// existing destination — without this, a second rotation in the same
// second would silently overwrite the first rotated file, permanently
// losing whatever audit history it held.
func uniqueRotatedPath(path string, now time.Time) (string, error) {
	base := fmt.Sprintf("%s.%s", path, now.UTC().Format("20060102T150405Z"))
	candidate := base
	for i := 1; ; i++ {
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", fmt.Errorf("audit: checking rotated path %s: %w", candidate, err)
		}
		candidate = fmt.Sprintf("%s.%d", base, i)
	}
}
