// Package audit is the single write path for ~/.damping/audit.jsonl.
// core/audit is the only component that appends to the audit log — CLI and
// MCP adapters normalize their intercepted actions into an event.ActionEvent
// and hand it here; they never write the file themselves. This is the
// concrete enforcement of the "single audit outlet" rule in
// docs/00-統一開發計畫（定案版）.md and features/audit_log.feature.
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// Append validates and writes one ActionEvent as a single JSON line.
func (w *Writer) Append(e event.ActionEvent) error {
	if err := e.Validate(); err != nil {
		return fmt.Errorf("audit: refusing to write invalid event: %w", err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return fmt.Errorf("audit: creating audit directory: %w", err)
	}
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: opening %s: %w", w.path, err)
	}
	defer f.Close()

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: encoding event: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: writing event: %w", err)
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

// ReadAll reads every ActionEvent from path and returns those matching f. A
// missing file is treated as an empty log, not an error — a brand new
// install with no interceptions yet is a normal state, not a failure.
func ReadAll(path string, f Filter) ([]event.ActionEvent, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: opening %s: %w", path, err)
	}
	defer file.Close()

	var out []event.ActionEvent
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e event.ActionEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return out, fmt.Errorf("audit: %s:%d: malformed record: %w", path, lineNo, err)
		}
		if f.Matches(e) {
			out = append(out, e)
		}
	}
	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("audit: reading %s: %w", path, err)
	}
	return out, nil
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
	rotatedPath := fmt.Sprintf("%s.%s", path, now.UTC().Format("20060102T150405Z"))
	if err := os.Rename(path, rotatedPath); err != nil {
		return false, fmt.Errorf("audit: rotating %s: %w", path, err)
	}
	return true, nil
}
