// Package mcp implements the V1 thin MCP adapter (`damping mcp wrap`) — see
// docs/architecture.md §7 and docs/00-統一開發計畫（定案版）.md §四修正三.
// Damping sits between an MCP client (launched by Claude Code's or Cursor's
// MCP server config, which now points at `damping mcp wrap -- <real
// server>` instead of the real server directly) and the real downstream
// MCP server: it discovers the wrapped server's tools, re-exposes them
// unchanged, and runs every outgoing tool call through the exact same
// core/policy engine and core/audit sink the CLI hook uses — before
// forwarding the call to the real subprocess.
//
// This is deliberately NOT a Gateway: no OAuth, no token inspection or
// re-issuance, no confused-deputy defense, no multi-tenant anything. That
// full enterprise-grade MCP governance is Phase 3's gateway/ module. See
// docs/architecture.md §7 for why the official MCP Go SDK has no built-in
// interceptor hook point, which is why this package exists as a real
// client+server pair rather than a thin wrapper around one.
//
// This file is the protocol wiring (Wrap, wrapTransport,
// registerForwardingTool, resolvePrompt); facts.go turns a discovered tool +
// call request into policy.Facts, the pure translation cli/shell does for
// CLI commands.
package mcp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amplify-lab/damping/cli/ui"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

const (
	implementationName    = "damping"
	implementationVersion = "0.1.0"
)

// Wrap launches serverCmd as an MCP server subprocess, discovers its tools
// via tools/list, and re-exposes them over this process's own stdin/stdout —
// running every outgoing tool call through engine and writer before
// forwarding it to the real subprocess. Wrap blocks until the outer client
// disconnects or ctx is cancelled. policyPath is the same policy.yaml engine
// was already loaded from — resolvePrompt needs it directly to persist an
// "always allow/deny" choice back into the file (see alwaysOverlay's doc
// comment for why an in-memory overlay is layered on top of that).
func Wrap(ctx context.Context, serverCmd []string, engine policy.Evaluator, policyPath string, writer *audit.Writer, actor string) error {
	if len(serverCmd) == 0 {
		return fmt.Errorf("mcp: no server command given (usage: damping mcp wrap -- <server-command...>)")
	}
	subprocess := exec.CommandContext(ctx, serverCmd[0], serverCmd[1:]...) // #nosec G204 -- serverCmd is the local user's own `damping mcp wrap -- <server-command>` argument, the explicit point of this command, not attacker-influenced input
	return wrapTransport(ctx, &gosdk.CommandTransport{Command: subprocess}, &gosdk.StdioTransport{}, engine, policyPath, writer, actor)
}

// wrapTransport is Wrap's transport-agnostic core: connect upstream (to the
// real server) as a client, re-expose its tools as a server on downstream
// (to the outer client). Split out from Wrap so tests can substitute
// mcp.NewInMemoryTransports() pairs instead of a real subprocess + this
// process's own stdio — see wrap_test.go.
func wrapTransport(ctx context.Context, upstream, downstream gosdk.Transport, engine policy.Evaluator, policyPath string, writer *audit.Writer, actor string) error {
	client := gosdk.NewClient(&gosdk.Implementation{Name: implementationName, Version: implementationVersion}, nil)
	cs, err := client.Connect(ctx, upstream, nil)
	if err != nil {
		return fmt.Errorf("mcp: connecting to wrapped server: %w", err)
	}
	defer func() {
		// Loud, not silent, on the way out — the same convention this
		// file's writer.Append error handling above uses. By this point
		// wrapTransport's own return value is already determined by
		// server.Run below, so there's nothing to propagate this into;
		// stderr is the last resort, not a place to drop it entirely.
		if cerr := cs.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "damping: closing connection to wrapped server: %v\n", cerr)
		}
	}()

	server := gosdk.NewServer(&gosdk.Implementation{Name: implementationName, Version: implementationVersion}, nil)

	// One overlay per wrapped session, shared across every tool this loop
	// registers below, so an "always" choice made on one tool call is
	// honored immediately by any other tool call in the same session too.
	overlay := &alwaysOverlay{}

	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return fmt.Errorf("mcp: listing tools from wrapped server: %w", err)
		}
		registerForwardingTool(server, cs, tool, engine, policyPath, overlay, writer, actor)
	}

	return server.Run(ctx, downstream)
}

// registerForwardingTool re-exposes one discovered tool on server, gating
// every call through engine/writer before forwarding it to cs (the client
// session connected to the real wrapped server).
func registerForwardingTool(server *gosdk.Server, cs *gosdk.ClientSession, tool *gosdk.Tool, engine policy.Evaluator, policyPath string, overlay *alwaysOverlay, writer *audit.Writer, actor string) {
	inputSchema := tool.InputSchema
	if inputSchema == nil {
		// Server.AddTool panics if InputSchema is nil or not type "object" —
		// a tool with no declared schema still needs a minimal valid one.
		inputSchema = map[string]any{"type": "object"}
	}
	forwarded := &gosdk.Tool{
		Name:         tool.Name,
		Description:  tool.Description,
		InputSchema:  inputSchema,
		OutputSchema: tool.OutputSchema,
		Annotations:  tool.Annotations,
	}

	server.AddTool(forwarded, func(ctx context.Context, req *gosdk.CallToolRequest) (*gosdk.CallToolResult, error) {
		facts := factsFromCall(tool, req)

		var d decision.Decision
		if v, ok := overlay.verdict(facts.Raw); ok {
			d = decision.Decision{Verdict: v, Reason: "matched an always-" + string(v) + " pattern set earlier this session"}
		} else {
			d = engine.Evaluate(facts)
			if d.Verdict == decision.Prompt {
				d = resolvePrompt(policyPath, overlay, facts.Raw, d)
			}
		}

		if writer != nil {
			ev := event.New(event.NewID(), sessionIDOf(req.Session), actor, event.ChannelMCP, event.ActionToolCall, tool.Name, facts.Raw, d)
			if err := writer.Append(ev); err != nil {
				// The audit sink is the one place with no deeper fallback to
				// log a failure to — silently discarding it would repeat the
				// exact class of bug sessionIDOf's own doc comment describes
				// (an invalid event silently vanishing instead of erroring
				// loudly). stderr is the last resort.
				fmt.Fprintf(os.Stderr, "damping: failed to write audit record: %v\n", err)
			}
		}

		if d.Outcome() == decision.Deny {
			return &gosdk.CallToolResult{
				IsError: true,
				Content: []gosdk.Content{&gosdk.TextContent{
					Text: fmt.Sprintf("damping: denied by policy (%s): %s", d.PolicyID, d.Reason),
				}},
			}, nil
		}

		return cs.CallTool(ctx, &gosdk.CallToolParams{Name: req.Params.Name, Arguments: req.Params.Arguments})
	})
}

// sessionIDOf returns a stable per-connection identifier for the audit
// trail. ServerSession.ID() is the real MCP session ID where the transport
// assigns one (e.g. Streamable HTTP, for reconnection tracking), but a
// stdio-based session — what `damping mcp wrap` always uses in V1 — has no
// such concept and ID() returns "". core/event.ActionEvent requires a
// non-empty SessionID (see core/event's Validate), so falling through to an
// empty string would make audit.Writer.Append fail validation and silently
// drop the record entirely — far worse than a slightly awkward fallback.
// The session object's own address is at least stable and unique for the
// lifetime of this one `damping mcp wrap` process.
func sessionIDOf(session *gosdk.ServerSession) string {
	if session == nil {
		return "unknown"
	}
	if id := session.ID(); id != "" {
		return id
	}
	return fmt.Sprintf("mcp-wrap-%p", session)
}

// resolvePrompt asks a human via the controlling terminal — see
// docs/architecture.md §6 for why this must be /dev/tty, not this
// process's own stdin/stdout (those are reserved for the MCP JSON-RPC
// stream with the outer client, exactly the same reasoning as the CLI hook
// entrypoint). An [A]/[D] "always" choice is persisted exactly like the CLI
// hook does — policy.AppendAlwaysPattern writes it into policyPath — and is
// also recorded in overlay so the rest of *this* long-lived `mcp wrap`
// session honors it immediately, without waiting for a future invocation to
// reload the policy file (see alwaysOverlay's doc comment for why that
// second step is necessary here but not for the one-shot CLI hook).
// newTTYPrompter is a package-level var (not a direct call to
// ui.OpenTTYPrompter) so tests can substitute a scripted fake reader
// instead of a real controlling terminal — the same pattern
// cli/cmd/hook.go uses for the identical reason.
var newTTYPrompter = ui.OpenTTYPrompter

// ttyPromptMu serializes TTY prompts within one `damping mcp wrap` process.
// Unlike the CLI hook (a fresh one-shot subprocess per command), a single
// `mcp wrap` process stays alive for the MCP client's whole session and can
// have the MCP SDK invoke registerForwardingTool's handler concurrently for
// simultaneous tool calls — without this, two Prompt-tier calls at once
// would interleave their prompt text and input reads on the same
// controlling terminal, producing a garbled, unanswerable mess. This does
// not address a *second*, separate `damping` process (the CLI hook, or
// another `mcp wrap`) prompting on the same terminal at the same time —
// that cross-process race is a documented, lower-priority known limitation.
var ttyPromptMu sync.Mutex

func resolvePrompt(policyPath string, overlay *alwaysOverlay, raw string, d decision.Decision) decision.Decision {
	ttyPromptMu.Lock()
	defer ttyPromptMu.Unlock()

	// Re-check overlay now that this goroutine actually holds the lock: two
	// concurrent calls for the exact same not-yet-decided raw both miss the
	// caller's pre-lock overlay check and both reach here, serialized by
	// ttyPromptMu — without this second check, the loser would re-prompt a
	// human for a call the winner (just ahead of it) already just resolved,
	// and could even persist a contradictory answer for the same raw string
	// into both always_allow and always_deny. Found via adversarial review,
	// not a test failure — go test -race stays clean either way, since this
	// was a race-free but logically wrong sequencing, not a data race.
	if v, ok := overlay.verdict(raw); ok {
		d.Resolve(v)
		d.Reason = "matched an always-" + string(v) + " pattern set earlier this session"
		return d
	}

	prompter, closeTTY, err := newTTYPrompter()
	if err != nil {
		d.Resolve(decision.Deny)
		d.Reason = "no controlling terminal available to ask; denied by default: " + d.Reason
		return d
	}
	defer closeTTY()
	resolution := prompter.Confirm(raw, d)
	d.Resolve(resolution.Verdict)
	if resolution.Persist {
		if err := policy.AppendAlwaysPattern(policyPath, resolution.Verdict, raw); err != nil {
			// Loud, not silent — the same principle as this file's other
			// no-deeper-fallback failure paths (see registerForwardingTool's
			// writer.Append error handling above).
			fmt.Fprintf(os.Stderr, "damping: failed to save always-%s pattern: %v\n", resolution.Verdict, err)
			prompter.Notify(fmt.Sprintf("Note: couldn't save this as an always-%s pattern (%v) — this choice applies to this call only.", resolution.Verdict, err))
		} else {
			overlay.record(resolution.Verdict, raw)
		}
	}
	return d
}
