package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/amplify-lab/damping/cli/adapter/agent"
	"github.com/amplify-lab/damping/cli/enforcement"
	"github.com/amplify-lab/damping/cli/update"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

// currentMethod and applyUpdate are handleVersion/handleUpdate's only calls
// into cli/update, reassigned as package-level vars (rather than called
// directly) purely so tests can substitute a fake self-update without ever
// executing a real curl-pipe-sh/brew/powershell command — see
// TestHandleUpdate_StreamsSuccessDoneFrame in server_test.go. Production
// code never reassigns these; they always resolve to the real functions.
var (
	currentMethod = update.CurrentMethod
	applyUpdate   = update.Apply
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
	if events, err := s.auditEvents(); err != nil {
		out.DegradedError = err.Error()
	} else {
		degraded := filterEvents(events, audit.Filter{Outcome: "degraded", Since: time.Now().Add(-7 * 24 * time.Hour)})
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
	return audit.ParseFilter(audit.FilterQuery{
		Channel:    q.Get("channel"),
		Risk:       q.Get("risk"),
		Actor:      q.Get("actor"),
		Outcome:    q.Get("outcome"),
		Since:      q.Get("since"),
		Until:      q.Get("until"),
		PolicyID:   q.Get("policy_id"),
		ActionType: q.Get("action_type"),
		Keyword:    q.Get("keyword"),
		Before:     q.Get("before"),
		SessionID:  q.Get("session_id"),
	})
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

	all, err := s.auditEvents()
	if err != nil {
		http.Error(w, fmt.Sprintf("reading audit log: %v", err), http.StatusInternalServerError)
		return
	}
	events := filterEvents(all, f)
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

// handlePolicy serves the active policy's rule list — id/description/risk/
// action per rule, straight off policy.Config.Rules (core/policy/config.go's
// RuleConfig now carries json tags for exactly this) — for the dashboard's
// "what does this actually protect against" explainer, opened from the
// summary strip's rule-count card. A separate endpoint from /api/summary
// (which only needs the *count*) since the full rule list is a distinct,
// larger payload only the explainer view needs to fetch, and only once —
// the client caches it rather than refetching on every open.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	cfg, err := policy.LoadConfig(s.cfg.PolicyPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("loading policy: %v", err), http.StatusInternalServerError)
		return
	}
	rules := cfg.Rules
	if rules == nil {
		rules = []policy.RuleConfig{} // never render as JSON null
	}
	writeJSON(w, rules)
}

// versionResponse is /api/version's response shape — the header's version
// label, its "update available" badge, and the confirmation panel opened
// from it all render straight off this, without duplicating any of
// cli/update's own detection logic (see cli/cmd/update.go for the terminal
// equivalent this mirrors).
type versionResponse struct {
	Current         string `json:"current"`
	Latest          string `json:"latest"`
	UpdateAvailable bool   `json:"update_available"`
	GithubURL       string `json:"github_url"`
	Method          string `json:"method"`
	Command         string `json:"command"`
	CanAutoUpdate   bool   `json:"can_auto_update"`
}

// githubURL is where the header's version label links out to, and the
// value /api/version reports as github_url.
const githubURL = "https://github.com/amplify-lab/damping"

// handleVersion reports this install's own update state: the same
// current/latest/available facts `damping update` already computes
// (cli/cmd/update.go), plus the exact self-update command
// currentMethod() would run. No auth beyond the existing Host-header check
// (unlike POST /api/update below) — this is read-only and reveals nothing
// an operator with a terminal on this machine couldn't already see by
// running `damping update` themselves.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	info := update.Check(r.Context(), s.cfg.Version)
	method := currentMethod()
	writeJSON(w, versionResponse{
		Current:         info.Current,
		Latest:          info.Latest,
		UpdateAvailable: info.Available,
		GithubURL:       githubURL,
		Method:          method.Kind,
		// Method.Display() (not a naive Executable+Args join): for "script"/
		// "windows", Args wraps the real command inside `sh -c "..."` /
		// `powershell -Command "..."` for exec.Command's own argv-based
		// invocation, and a plain space-join loses that inner quoting — see
		// Display's own doc comment in cli/update/method.go. Using it here
		// keeps the dashboard and `damping update`'s terminal output
		// (cli/cmd/update.go) always showing the identical command for
		// identical state, rather than two independent renderings that can
		// drift.
		Command:       method.Display(),
		CanAutoUpdate: info.Available && !method.NeedsElevation,
	})
}

// dashboardHeader is the custom header POST /api/update requires before
// doing anything else at all.
//
// This dashboard has NO AUTHENTICATION by design (see this package's own
// doc comment), and Handler's Host-header check above defends specifically
// against DNS rebinding — neither stops a plain cross-origin CSRF POST: a
// malicious webpage open in the same browser, at the same time `damping
// dashboard` happens to be running, can fire a blind cross-origin
// fetch/form POST straight at http://127.0.0.1:<port>/api/update with a
// real, matching Host header (no rebinding involved at all), and a simple
// POST triggers no CORS preflight on its own. Since this endpoint replaces
// the user's installed binary, that gap is unacceptable.
//
// Requiring this custom header closes it: a custom request header forces
// the browser to CORS-preflight the request first, and since this server
// never sends an Access-Control-Allow-Origin header, the browser's own
// same-origin policy fails that preflight and never sends the real POST at
// all for a cross-origin caller. This is the same pattern Vite's and
// webpack-dev-server's local dev servers use to protect themselves from
// requests originating from any other page open in the browser — it is not
// optional boilerplate, it is the actual CSRF defense for this endpoint.
// The re-checks in handleUpdate below (NeedsElevation, the in-flight guard)
// are real safety nets, but this header is the gate that keeps an
// arbitrary web page from ever reaching them.
const dashboardHeader = "X-Damping-Dashboard"

// remoteAddrIsLoopback reports whether remoteAddr — an *http.Request's own
// RemoteAddr, the actual TCP peer address net/http records for the
// connection, never anything a client can spoof via a header — is a
// loopback address. This is POST /api/update's actual defense against the
// 0.0.0.0 case: if the operator starts `damping dashboard --host 0.0.0.0`
// (cli/cmd/dashboard.go warns loudly about that choice at startup), the
// dashboardHeader check above stops a malicious webpage's cross-origin
// fetch, but does nothing at all against a plain `curl` from another
// machine on the same network — curl can set any header it likes, no
// browser/CORS involved. Since this endpoint replaces the user's installed
// binary, a stranger elsewhere on the LAN reaching it at all is
// unacceptable, independent of --host: this check runs regardless of what
// BindHost the server was configured with (unlike checkHostHeader in
// server.go, which deliberately steps aside once bound to 0.0.0.0).
func remoteAddrIsLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // no port present (unusual, but be lenient) — try the whole value as a bare address
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// updateDoneFrame is the final SSE frame handleUpdate always sends, win or
// lose — the client's fetch-based reader (index.html cannot use
// EventSource here; see its own comment on why) treats this as the signal
// to stop reading and show a terminal success/failure state.
type updateDoneFrame struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// handleUpdate runs this install's self-update in place and streams its
// output back as it happens, using exactly the SSE framing
// handleEventStream already established (same headers, same Flusher check,
// same "data: <line>\n\n" convention with embedded newlines flattened, same
// "event: error\ndata: ...\n\n" convention on failure) — plus a final
// "event: done" frame the client uses to know the stream is over and
// whether it succeeded.
//
// Security-critical: read dashboardHeader's and remoteAddrIsLoopback's doc
// comments above before touching this function. In order:
//
//  1. Reject anything whose RemoteAddr isn't loopback — see
//     remoteAddrIsLoopback's doc comment for why this must run regardless
//     of --host.
//  2. Reject anything without the dashboardHeader header — the CSRF gate
//     for a same-machine browser; see dashboardHeader's doc comment for why.
//  3. The request body is never read at all. method (and the command line
//     derived from it) is always recomputed fresh, server-side, via
//     currentMethod() — nothing the client could send in a body, query
//     string, or otherwise ever reaches exec.Command. There is no
//     command-injection surface on this endpoint.
//  4. NeedsElevation is re-checked fresh, server-side, right here — never
//     trusted from any client-sent "I confirmed" signal. The checks above
//     are the real security gates; this is a correctness backstop against
//     ever actually running an installer that needs privileges this
//     process doesn't have.
//  5. updateInFlight guards against two concurrent runs: a second POST
//     arriving while one is already applying gets 409 Conflict, never a
//     second concurrent install.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if !remoteAddrIsLoopback(r.RemoteAddr) {
		http.Error(w, "damping dashboard: rejected — POST /api/update only accepts requests originating from this machine itself, regardless of --host (see remoteAddrIsLoopback's doc comment in cli/dashboard/handlers.go)", http.StatusForbidden)
		return
	}
	if r.Header.Get(dashboardHeader) != "1" {
		http.Error(w, "damping dashboard: missing "+dashboardHeader+" header — see handleUpdate's doc comment in cli/dashboard/handlers.go", http.StatusForbidden)
		return
	}

	method := currentMethod()
	if method.NeedsElevation {
		http.Error(w, "damping dashboard: this install needs elevated privileges to update — damping won't request them on your behalf; run the command shown in the dashboard yourself", http.StatusForbidden)
		return
	}

	if !s.updateInFlight.CompareAndSwap(false, true) {
		http.Error(w, "damping dashboard: an update is already in progress", http.StatusConflict)
		return
	}
	defer s.updateInFlight.Store(false)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// context.WithoutCancel: a browser disconnecting mid-update (tab closed,
	// laptop sleeps, network blip) cancels r.Context() — but this replaces
	// the running binary on disk, and a half-applied update on cancel is
	// worse than a client that never sees the result. The update always runs
	// to completion server-side; streaming its output back stays
	// best-effort (see sseLineWriter.Write below — writes to a gone client
	// just fail silently rather than aborting the install).
	applyErr := applyUpdate(context.WithoutCancel(r.Context()), method, sseLineWriter{w: w, flusher: flusher})

	done := updateDoneFrame{OK: applyErr == nil}
	if applyErr != nil {
		msg := strings.ReplaceAll(applyErr.Error(), "\n", " ")
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", msg) // #nosec G705 -- msg is update.Apply's own wrapped error text (installer exit status/I/O failures), never attacker-supplied, and is never rendered as HTML by this dashboard's client-side JS (see index.html)
		flusher.Flush()
		done.Error = applyErr.Error()
	}
	data, err := json.Marshal(done)
	if err != nil {
		data = []byte(`{"ok":false}`)
	}
	fmt.Fprintf(w, "event: done\ndata: %s\n\n", data)
	flusher.Flush()
}

// sseLineWriter adapts update.Apply's combined stdout+stderr into the same
// SSE "data: <line>\n\n" framing handleEventStream's own error frame uses —
// one frame per Write call, flushed immediately, with any newline embedded
// in a single payload flattened to a space (the SSE spec requires each line
// of a "data:" payload to carry its own "data:" prefix; left as-is, a
// multi-line installer output chunk would truncate at the first line
// break).
type sseLineWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (sw sseLineWriter) Write(p []byte) (int, error) {
	line := strings.ReplaceAll(string(p), "\n", " ")
	// Best-effort, deliberately: this is update.Apply's cmd.Stdout, wired
	// through context.WithoutCancel (handleUpdate) so a disconnected client
	// never aborts the running update — a write failing here (broken pipe,
	// client gone) must not propagate as a Write error either, or
	// exec.Cmd's own stdout-copy goroutine would surface it as a command
	// failure and the update would be reported as failed even though it's
	// still running/succeeding server-side. Always reporting success to the
	// caller (len(p), nil) is what makes that true regardless of whether
	// anyone is still listening.
	_, _ = fmt.Fprintf(sw.w, "data: %s\n\n", line)
	sw.flusher.Flush()
	return len(p), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
