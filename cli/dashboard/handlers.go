package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/amplify-lab/damping/cli/adapter/agent"
	"github.com/amplify-lab/damping/cli/enforcement"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

// summary is /api/summary's response shape — the same facts `damping
// status` prints as a headline/Policy/Agents table, in JSON so the
// dashboard's header strip can render them (docs/ux-dashboard-spec.md
// §2.2's "top strip", scoped down from team stats to this one local
// install's own state).
type summary struct {
	Enabled         bool     `json:"enabled"`
	PolicyPath      string   `json:"policy_path"`
	PolicyError     string   `json:"policy_error,omitempty"`
	RuleCount       int      `json:"rule_count"`
	Agents          []string `json:"agents"`
	DegradedCount7d int      `json:"degraded_count_7d"`
	DegradedError   string   `json:"degraded_error,omitempty"`
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	disabled, err := enforcement.IsDisabled()
	if err != nil {
		http.Error(w, fmt.Sprintf("checking enforcement state: %v", err), http.StatusInternalServerError)
		return
	}

	out := summary{Enabled: !disabled, PolicyPath: s.cfg.PolicyPath}
	if cfg, cfgErr := policy.LoadConfig(s.cfg.PolicyPath); cfgErr != nil {
		out.PolicyError = cfgErr.Error()
	} else {
		out.RuleCount = len(cfg.Rules)
	}

	for _, a := range agent.Registry {
		if has, err := a.HasHook(a.ConfigPath()); err == nil && has {
			out.Agents = append(out.Agents, a.Name)
		}
	}

	// A prior version silently left DegradedCount7d at its zero value on any
	// read error — a false all-clear, inconsistent with handleEvents below,
	// which correctly turns the identical error into an HTTP 500. Surfaced
	// as a field instead (like PolicyError above) rather than failing this
	// whole request, since the rest of the summary is still valid even if
	// this one check couldn't complete.
	if degraded, err := audit.ReadAll(s.cfg.AuditPath, audit.Filter{Outcome: "degraded", Since: time.Now().Add(-7 * 24 * time.Hour)}); err != nil {
		out.DegradedError = err.Error()
	} else {
		out.DegradedCount7d = len(degraded)
	}

	writeJSON(w, out)
}

// parseFilterQuery reads the same filter vocabulary damping log's flags use
// (docs/ux-dashboard-spec.md §4's "CLI/dashboard vocabulary parity") off
// URL query parameters, through the one shared core/audit.ParseFilter
// implementation.
func parseFilterQuery(r *http.Request) (audit.Filter, error) {
	q := r.URL.Query()
	return audit.ParseFilter(q.Get("channel"), q.Get("risk"), q.Get("actor"), q.Get("outcome"), q.Get("since"))
}

// defaultEventsLimit caps /api/events when the caller doesn't pass an
// explicit ?limit= — unlike `damping log`, whose own --limit defaults to 0
// (unbounded) because a terminal user can scroll or pipe through `less`,
// this response gets re-rendered as DOM rows in a live browser tab on every
// filter change, so an install with a very large audit history shouldn't
// silently try to hand the whole thing over by default. An explicit
// ?limit=0 still means unlimited, matching the CLI's own vocabulary — this
// default only fills in the gap when the caller says nothing at all.
const defaultEventsLimit = 200

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilterQuery(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid filter: %v", err), http.StatusBadRequest)
		return
	}
	limit := defaultEventsLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid limit: %v", err), http.StatusBadRequest)
			return
		}
		limit = n
	}

	events, err := audit.ReadAll(s.cfg.AuditPath, f)
	if err != nil {
		http.Error(w, fmt.Sprintf("reading audit log: %v", err), http.StatusInternalServerError)
		return
	}
	limited := audit.LimitMostRecent(events, limit)
	if len(limited) < len(events) {
		// docs/ux-dashboard-spec.md §4's "never silently drop data" applies
		// here even though this truncation is a sane default rather than
		// something the user explicitly asked for (unlike `damping log
		// --limit N`, where the flag itself is the visible signal) — a
		// header, not a body-shape change, so plain `curl | jq` consumers
		// of this endpoint still get a bare JSON array.
		w.Header().Set("X-Damping-Truncated", "true")
	}
	events = limited
	if events == nil {
		events = []event.ActionEvent{} // never render as JSON null — the client always gets a real (possibly empty) array
	}
	writeJSON(w, events)
}

// handleEventStream is the dashboard's answer to docs/ux-dashboard-spec.md
// §2.3's "real-time table" — the team dashboard's spec calls for a
// WebSocket via Durable Objects Hibernation, which needs the Cloudflare
// backend this local slice deliberately has none of. Server-Sent Events
// over core/audit.Follow gets the same "new events appear without a
// reload" UX from a single local process with no extra dependency — the
// same polling-based Follow `damping log --follow` already uses.
func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilterQuery(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid filter: %v", err), http.StatusBadRequest)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// The client already has every pre-existing event from its own
	// /api/events fetch before it opens this connection (see index.html's
	// startStream, called right after loadEvents) — starting Follow at
	// offset 0 here would replay the entire audit log as if every event
	// were new, duplicating every row already on screen. The real
	// os.FileInfo (not just its Size()) is captured the same way `damping
	// log --follow`'s own startInfo is (cli/cmd/log.go), so only events
	// appended after this connection opens ever reach the client, and
	// Follow's first internal check has a real identity to compare against.
	var startInfo os.FileInfo
	if info, statErr := os.Stat(s.cfg.AuditPath); statErr == nil {
		startInfo = info
	} else if !os.IsNotExist(statErr) {
		http.Error(w, fmt.Sprintf("stat audit log: %v", statErr), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	err = audit.Follow(r.Context(), s.cfg.AuditPath, startInfo, f, 500*time.Millisecond, func(e event.ActionEvent) error {
		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	})
	// A client disconnecting cancels r.Context(), which Follow treats as a
	// normal stop (returns nil) — nothing left to report in that case.
	if err != nil {
		// The connection is already committed to text/event-stream with a
		// 200 status by this point, so a plain http.Error would just get
		// silently appended as an unparsable event — send it as a real SSE
		// "error" event instead, so the client's onerror/addEventListener
		// path can actually see it. Newlines are stripped because the SSE
		// spec requires each line of a "data:" payload to carry its own
		// "data:" prefix — left as-is, an error containing one would
		// truncate the frame at the first line break.
		msg := strings.ReplaceAll(err.Error(), "\n", " ")
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", msg) // #nosec G705 -- msg is Follow's own internal error text (file I/O/JSON-marshal failures), never attacker-supplied, and is never rendered as HTML by this dashboard's client-side JS (see index.html)
		flusher.Flush()
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
