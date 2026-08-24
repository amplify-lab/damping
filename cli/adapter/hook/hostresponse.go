package hook

import (
	"encoding/json"
	"io"

	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

// This file implements the response half of `damping hook pretooluse
// --hook-json` — the opt-in mode for an application that embeds an agent
// SDK and renders its own permission UI (a desktop app, an IDE), rather
// than an agent running at a terminal.
//
// The problem it solves: Damping's own confirmation prompt talks to the
// controlling terminal (docs/cli-reference.md §12), and a Prompt-tier
// decision with nothing to ask defaults to deny. For an unattended CLI
// agent that is the correct fail-closed default. For a desktop host it is
// the wrong one twice over — there IS a human present, and the host has a
// perfectly good dialog to ask them with — so every Prompt-tier rule (most
// of the shipped policy) would otherwise become a silent hard block the
// user can't answer.
//
// Why it must stay an explicit flag, never an automatic "no TTY, so ask"
// fallback: that automatic version was prototyped and deliberately parked
// (branch experiment/tty-ask-fallback, 2026-07-06). Claude Code's own
// "auto" permission mode silently treats an "ask" response as allow
// (Anthropic-confirmed, closed as not planned), and Cursor's shipped ask
// handling has been reported to run the command with no prompt at all.
// Both fail in the unsafe direction, so a hook that guesses its way into
// "ask" is a downgrade for CLI users. Passing --hook-json is a host making
// a promise instead: I will put this question in front of a human myself.

// HostDialect selects which hook-response vocabulary the JSON body speaks.
// It follows the shape of the payload that arrived, not the --actor label:
// a host embedding Claude Code's SDK sends a PreToolUse payload and expects
// Claude Code's response contract back.
type HostDialect string

const (
	// DialectClaudeCode is the PreToolUse contract Claude Code documents and
	// Codex reimplements: {"hookSpecificOutput":{"hookEventName":"PreToolUse",
	// "permissionDecision":"allow"|"deny"|"ask","permissionDecisionReason":"..."}}.
	DialectClaudeCode HostDialect = "claude-code"
	// DialectCursor is Cursor's beforeShellExecution contract:
	// {"permission":"allow"|"deny"|"ask","user_message":"...","agent_message":"..."}.
	DialectCursor HostDialect = "cursor"
)

// Host decision values — what the embedding host is being told to do. These
// are deliberately not decision.Verdict: "ask" is not a policy verdict but
// a handoff, and "prompt" would misdescribe what the host must now do.
const (
	HostDecisionAllow = "allow"
	HostDecisionDeny  = "deny"
	HostDecisionAsk   = "ask"
)

// HostResponse is the single JSON object `--hook-json` writes to stdout,
// exactly once per invocation. It carries two layers: the calling agent
// SDK's own hook contract (so a host can forward it straight through), and
// a "damping" block with everything the host needs to render a decent
// confirmation dialog — which rule fired, at what risk, and the audit event
// id the decision was recorded under.
//
// Unknown fields are ignored by every agent's hook parser, which is what
// makes the extra block safe to include.
type HostResponse struct {
	HookSpecificOutput *hookSpecificOutput `json:"hookSpecificOutput,omitempty"`

	// Cursor dialect fields — mutually exclusive with HookSpecificOutput.
	Permission   string `json:"permission,omitempty"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`

	Damping HostDecision `json:"damping"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// HostDecision is Damping's own, dialect-independent account of what it
// decided. A host should switch on Decision and show Reason; everything
// else is for its UI and its own logs.
type HostDecision struct {
	// Decision is what the host must do now: "allow" (Damping has no
	// objection), "deny" (blocked — do not run it), or "ask" (Damping wants
	// this confirmed by a human, and is trusting the host to do the asking).
	Decision string `json:"decision"`
	// Verdict is the raw policy verdict before any deferral or fallback —
	// "prompt" whenever Decision is "ask".
	Verdict    string `json:"verdict"`
	PolicyID   string `json:"policyId,omitempty"`
	Risk       string `json:"risk,omitempty"`
	Reason     string `json:"reason,omitempty"`
	EventID    string `json:"eventId,omitempty"`
	Channel    string `json:"channel,omitempty"`
	ActionType string `json:"actionType,omitempty"`
	Target     string `json:"target,omitempty"`
	// Degraded marks a decision made under an internal Damping failure
	// rather than a real policy match (docs/threat-model.md §6). The action
	// is allowed through — Damping cannot fail closed once the agent's own
	// hook contract takes over — but a host that surfaces this is the
	// difference between "protection ran and said yes" and "protection
	// wasn't running at all."
	Degraded bool `json:"degraded,omitempty"`
	// Version is the damping binary that produced this response, so a host
	// can feature-detect rather than parse a --version call separately.
	Version string `json:"version"`
}

// HostResponseInput is everything BuildHostResponse needs from the caller;
// see cli/cmd/hook.go for the single construction site.
type HostResponseInput struct {
	Dialect    HostDialect
	Decision   decision.Decision
	Deferred   bool // a Prompt-tier decision handed to the host to ask a human about
	EventID    string
	Channel    event.Channel
	ActionType event.ActionType
	Target     string
	Version    string
}

// BuildHostResponse renders a finished decision into the host-facing body.
//
// The one rule worth stating outright: an allowed action NEVER emits
// permissionDecision "allow". In the Claude Code contract that value means
// "skip the host's own permission flow entirely" — so emitting it would
// have Damping auto-approving actions on the user's behalf, including ones
// the host's own policy would have stopped. "Damping has no objection" and
// "approved" are different statements, and a guardrail is only entitled to
// make the first one. The same reasoning applies to Cursor's "allow".
func BuildHostResponse(in HostResponseInput) HostResponse {
	d := in.Decision
	hostDecision := HostDecisionAllow
	switch {
	case in.Deferred:
		hostDecision = HostDecisionAsk
	case d.Outcome() == decision.Deny:
		hostDecision = HostDecisionDeny
	}

	resp := HostResponse{
		Damping: HostDecision{
			Decision:   hostDecision,
			Verdict:    string(d.Verdict),
			PolicyID:   d.PolicyID,
			Risk:       d.Risk,
			Reason:     d.Reason,
			EventID:    in.EventID,
			Channel:    string(in.Channel),
			ActionType: string(in.ActionType),
			Target:     in.Target,
			Degraded:   d.Degraded,
			Version:    in.Version,
		},
	}
	if hostDecision == HostDecisionAllow {
		return resp // nothing to tell the agent's own permission layer
	}

	if in.Dialect == DialectCursor {
		resp.Permission = hostDecision
		resp.UserMessage = d.Reason
		resp.AgentMessage = d.Reason
		return resp
	}
	resp.HookSpecificOutput = &hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       hostDecision,
		PermissionDecisionReason: d.Reason,
	}
	return resp
}

// WriteHostResponse writes the body as a single line of JSON. Callers write
// it exactly once per invocation, after the decision is final — a host
// parsing stdout must never have to guess which of several objects is the
// real answer.
func WriteHostResponse(w io.Writer, resp HostResponse) error {
	return json.NewEncoder(w).Encode(resp)
}
