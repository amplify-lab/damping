// Package dashboard implements damping's local, single-user audit-log
// viewer: a small HTTP server (wired up by `damping dashboard`, see
// cli/cmd/dashboard.go) that renders the same ~/.damping/audit.jsonl
// `damping log` already reads, in a browser instead of a terminal table.
//
// This is deliberately NOT Phase 4's team dashboard from
// docs/ux-dashboard-spec.md — that's a separate, not-yet-built React+TS app
// on Cloudflare requiring a hosted backend and an SSO vendor decision, both
// genuinely blocked pending decisions only Tim can make. This package
// borrows that spec's visual language (dark theme, risk-as-temperature
// color, the damped-oscillation motif) and its "CLI/dashboard vocabulary
// parity" principle (§4) for a fully local, zero-infrastructure slice: no
// auth, no team sync, no cloud calls — it binds to 127.0.0.1 by default and
// reads the same local audit file `damping log` already does, nothing more.
package dashboard

import (
	"embed"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

//go:embed static/dashboard.css static/index.html static/charts.js
var staticFS embed.FS

// Config is everything the dashboard needs already resolved before it
// starts — plain paths, not cobra flags, so this package stays independent
// of the command-line layer that constructs it (cli/cmd/dashboard.go).
type Config struct {
	AuditPath  string
	PolicyPath string

	// BindHost is the --host value `damping dashboard` was started with
	// (e.g. "127.0.0.1", its default). It exists purely so Handler's
	// Host-header check (below) knows whether to enforce it: enforcing it
	// only makes sense while genuinely bound to a fixed local address —
	// see hostHeaderAllowed's doc comment.
	BindHost string

	// Version is the running binary's own version string (root.go's
	// Version var — "dev" for a non-release build). Passed through rather
	// than read internally so this package stays independent of cli/cmd,
	// the same reasoning as AuditPath/PolicyPath above. Used by
	// GET /api/version to report the current/latest/update-available state
	// the header's version badge renders.
	Version string
}

// Server serves the local dashboard's HTTP surface: one HTML shell, one
// static stylesheet, and a small JSON/SSE API the shell's own inline
// JavaScript calls — no separate frontend build step, no Node toolchain.
type Server struct {
	cfg Config

	// updateInFlight guards POST /api/update against a second concurrent
	// run — set with CompareAndSwap before Apply starts, cleared in a
	// defer once it finishes. A plain bool would race under -race given
	// this handler can genuinely be invoked concurrently (nothing else
	// serializes HTTP handlers); atomic.Bool makes the check-and-set a
	// single atomic operation instead of two.
	updateInFlight atomic.Bool

	// auditCache caches audit.jsonl's parsed events across requests, keyed
	// by (size, mtime), so the JSON endpoints that all read the same file
	// (handleSummary, handleEvents, handleStats, handleSessions) don't each
	// re-read and re-decode it independently on every poll — see
	// audit_cache.go's own doc comment for the full reasoning.
	auditCache auditSnapshot
}

// NewServer builds a Server for cfg. Call Handler to get the http.Handler
// to serve — via net/http.ListenAndServe for the real `damping dashboard`
// command, or httptest.NewServer for tests.
func NewServer(cfg Config) *Server {
	return &Server{cfg: cfg}
}

// Handler returns the dashboard's full routing table, wrapped in a
// Host-header check — a review caught that binding to 127.0.0.1 alone does
// NOT stop a malicious webpage from reading this unauthenticated server via
// DNS rebinding (the browser resolves an attacker-controlled domain to
// 127.0.0.1 mid-session, then treats a request as same-origin with that
// domain even though it's really talking to this server). Checking the
// Host header defeats that: a rebound request still carries the attacker's
// domain as its Host, which never matches a real local address.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /static/dashboard.css", s.handleCSS)
	mux.HandleFunc("GET /static/charts.js", s.handleChartsJS)
	mux.HandleFunc("GET /api/summary", s.handleSummary)
	mux.HandleFunc("GET /api/policy", s.handlePolicy)
	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("GET /api/sessions", s.handleSessions)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("GET /api/events/stream", s.handleEventStream)
	mux.HandleFunc("GET /api/version", s.handleVersion)
	mux.HandleFunc("POST /api/update", s.handleUpdate)
	return checkHostHeader(s.cfg.BindHost, mux)
}

func checkHostHeader(bindHost string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostHeaderAllowed(bindHost, r.Host) {
			http.Error(w, "damping dashboard: rejected — this request's Host header doesn't match a local address (DNS-rebinding protection)", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostHeaderAllowed reports whether host (an incoming request's Host
// header, e.g. "127.0.0.1:4243" or an attacker's rebound domain) is safe to
// serve. Enforcement only applies while bindHost is itself a fixed local
// address (the default "127.0.0.1", "localhost", or empty/unset, as in
// tests) — once an operator explicitly binds elsewhere (e.g. "0.0.0.0" to
// expose this on a LAN), `damping dashboard` already prints a loud warning
// about that choice (see cli/cmd/dashboard.go), and there is no single
// "correct" Host value left to allowlist against a bind-all address, so
// this check steps aside rather than guess.
func hostHeaderAllowed(bindHost, host string) bool {
	if !isLocalBindHost(bindHost) {
		return true
	}
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	switch strings.ToLower(h) {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	default:
		return false
	}
}

func isLocalBindHost(h string) bool {
	switch strings.ToLower(h) {
	case "", "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	default:
		return false
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "dashboard: embedded index.html missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleCSS(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/dashboard.css")
	if err != nil {
		http.Error(w, "dashboard: embedded dashboard.css missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleChartsJS(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/charts.js")
	if err != nil {
		http.Error(w, "dashboard: embedded charts.js missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = w.Write(data)
}
