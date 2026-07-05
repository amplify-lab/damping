package mcp

import (
	"sync"

	"github.com/amplify-lab/damping/core/decision"
)

// alwaysOverlay is an in-memory mirror of what policy.AppendAlwaysPattern
// just persisted to disk for this process's lifetime. `damping mcp wrap` is
// a single long-lived process for an entire MCP client session — unlike
// the one-shot `damping hook pretooluse` subprocess, which simply re-loads
// policy.yaml from disk on its very next invocation, a wrap process never
// reconstructs its policy.Evaluator mid-session. Without this overlay, an
// "Always allow"/"Always deny" choice would be correctly saved to disk for
// the *next* `damping mcp wrap` run, but the operator would still be
// re-prompted for the exact same call for the rest of *this* run — not
// what "always" means to someone answering the prompt right now. Patterns
// are matched by exact value only (never a wildcard), matching how
// AppendAlwaysPattern itself persists — see its doc comment.
//
// Caveat inherited from that same exact-match design (not introduced here):
// the matched value is facts.Raw, the tool name plus its raw JSON argument
// bytes (see rawCallSummary in facts.go). Two calls a human would consider
// "the exact same call" only match if the calling MCP client serializes
// those arguments identically byte-for-byte every time — a client that
// varies key order, whitespace, or number formatting across otherwise
// logically-identical calls would defeat both this overlay and the on-disk
// pattern equally. Damping's own code introduces no such variance (it
// passes through req.Params.Arguments, the raw wire bytes, untouched).
type alwaysOverlay struct {
	mu    sync.Mutex
	allow map[string]bool
	deny  map[string]bool
}

// verdict reports the overlay's remembered decision for raw, if any.
func (o *alwaysOverlay) verdict(raw string) (decision.Verdict, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.deny[raw] {
		return decision.Deny, true
	}
	if o.allow[raw] {
		return decision.Allow, true
	}
	return "", false
}

// record adds raw to the overlay's allow or deny set. Called only after
// AppendAlwaysPattern has successfully written the same pattern to disk, so
// the in-memory overlay never claims a persistence guarantee the on-disk
// policy file doesn't actually back up.
func (o *alwaysOverlay) record(verdict decision.Verdict, raw string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	switch verdict {
	case decision.Allow:
		if o.allow == nil {
			o.allow = make(map[string]bool)
		}
		o.allow[raw] = true
	case decision.Deny:
		if o.deny == nil {
			o.deny = make(map[string]bool)
		}
		o.deny[raw] = true
	}
}
