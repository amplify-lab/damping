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
// disconnects or ctx is cancelled.
func Wrap(ctx context.Context, serverCmd []string, engine *policy.Engine, writer *audit.Writer, actor string) error {
	if len(serverCmd) == 0 {
		return fmt.Errorf("mcp: no server command given (usage: damping mcp wrap -- <server-command...>)")
	}
	subprocess := exec.CommandContext(ctx, serverCmd[0], serverCmd[1:]...)
	return wrapTransport(ctx, &gosdk.CommandTransport{Command: subprocess}, &gosdk.StdioTransport{}, engine, writer, actor)
}

// wrapTransport is Wrap's transport-agnostic core: connect upstream (to the
// real server) as a client, re-expose its tools as a server on downstream
// (to the outer client). Split out from Wrap so tests can substitute
// mcp.NewInMemoryTransports() pairs instead of a real subprocess + this
// process's own stdio — see wrap_test.go.
func wrapTransport(ctx context.Context, upstream, downstream gosdk.Transport, engine *policy.Engine, writer *audit.Writer, actor string) error {
	client := gosdk.NewClient(&gosdk.Implementation{Name: implementationName, Version: implementationVersion}, nil)
	cs, err := client.Connect(ctx, upstream, nil)
	if err != nil {
		return fmt.Errorf("mcp: connecting to wrapped server: %w", err)
	}
	defer cs.Close()

	server := gosdk.NewServer(&gosdk.Implementation{Name: implementationName, Version: implementationVersion}, nil)

	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return fmt.Errorf("mcp: listing tools from wrapped server: %w", err)
		}
		registerForwardingTool(server, cs, tool, engine, writer, actor)
	}

	return server.Run(ctx, downstream)
}

// registerForwardingTool re-exposes one discovered tool on server, gating
// every call through engine/writer before forwarding it to cs (the client
// session connected to the real wrapped server).
func registerForwardingTool(server *gosdk.Server, cs *gosdk.ClientSession, tool *gosdk.Tool, engine *policy.Engine, writer *audit.Writer, actor string) {
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
		d := engine.Evaluate(facts)

		if d.Verdict == decision.Prompt {
			d = resolvePrompt(facts.Raw, d)
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
// entrypoint). Persisting an "always allow/deny" resolution for MCP tool
// calls is not yet implemented in V1 — see docs/architecture.md §7's note
// on scope — a Prompt decision is resolved once, per call, every time.
func resolvePrompt(raw string, d decision.Decision) decision.Decision {
	prompter, closeTTY, err := ui.OpenTTYPrompter()
	if err != nil {
		d.Resolve(decision.Deny)
		d.Reason = "no controlling terminal available to ask; denied by default: " + d.Reason
		return d
	}
	defer closeTTY()
	resolution := prompter.Confirm(raw, d)
	d.Resolve(resolution.Verdict)
	return d
}
