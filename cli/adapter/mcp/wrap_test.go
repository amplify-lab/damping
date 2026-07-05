package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amplify-lab/damping/cli/ui"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

func boolPtr(b bool) *bool { return &b }

// startFakeRealServer stands in for the actual downstream MCP server that
// `damping mcp wrap` would normally launch as a subprocess. It exposes two
// tools: a read-only one and one explicitly annotated destructive — exactly
// the distinction cli/adapter/mcp's default-active policy rule
// (mcp.destructive_tool_call) is meant to catch.
func startFakeRealServer(t *testing.T, ctx context.Context, transport gosdk.Transport) {
	t.Helper()
	server := gosdk.NewServer(&gosdk.Implementation{Name: "fake-real-server", Version: "0.0.1"}, nil)

	server.AddTool(&gosdk.Tool{
		Name:        "read_thing",
		Description: "reads a thing",
		InputSchema: map[string]any{"type": "object"},
		Annotations: &gosdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, req *gosdk.CallToolRequest) (*gosdk.CallToolResult, error) {
		return &gosdk.CallToolResult{Content: []gosdk.Content{&gosdk.TextContent{Text: "read ok"}}}, nil
	})

	server.AddTool(&gosdk.Tool{
		Name:        "delete_all",
		Description: "deletes everything",
		InputSchema: map[string]any{"type": "object"},
		Annotations: &gosdk.ToolAnnotations{DestructiveHint: boolPtr(true)},
	}, func(ctx context.Context, req *gosdk.CallToolRequest) (*gosdk.CallToolResult, error) {
		return &gosdk.CallToolResult{Content: []gosdk.Content{&gosdk.TextContent{Text: "deleted"}}}, nil
	})

	if _, err := server.Connect(ctx, transport, nil); err != nil {
		t.Fatalf("connecting fake real server: %v", err)
	}
}

// setupWrap wires: fake real server <-in-memory-> damping (wrapTransport,
// running in a goroutine) <-in-memory-> a test client. It returns the test
// client's session, ready to call tools through the whole real pipeline.
func setupWrap(t *testing.T, engine *policy.Engine, writer *audit.Writer) *gosdk.ClientSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	upstreamServerSide, upstreamDampingSide := gosdk.NewInMemoryTransports()
	downstreamDampingSide, downstreamClientSide := gosdk.NewInMemoryTransports()

	startFakeRealServer(t, ctx, upstreamServerSide)

	go func() {
		_ = wrapTransport(ctx, upstreamDampingSide, downstreamDampingSide, engine, writer, "test-client")
	}()

	client := gosdk.NewClient(&gosdk.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	cs, err := client.Connect(ctx, downstreamClientSide, nil)
	if err != nil {
		t.Fatalf("connecting test client: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func loadTestEngine(t *testing.T) *policy.Engine {
	t.Helper()
	path := filepath.Join("..", "..", "policies", "default.yaml")
	cfg, err := policy.LoadConfig(path)
	if err != nil {
		t.Fatalf("loading default policy: %v", err)
	}
	return policy.New(cfg)
}

func TestWrap_ForwardsReadOnlyToolCallAndAllows(t *testing.T) {
	engine := loadTestEngine(t)
	writer := audit.NewWriter(filepath.Join(t.TempDir(), "audit.jsonl"))
	cs := setupWrap(t, engine, writer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &gosdk.CallToolParams{Name: "read_thing"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected a read-only tool call to succeed, got error result: %+v", result)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content forwarded from the real server")
	}
}

// TestWrap_DeniesDestructiveToolCall proves the actual point of this
// package: a tool the server declares destructive is intercepted and never
// reaches the real subprocess — the fake server's "deleted" response must
// NOT come back.
func TestWrap_DeniesDestructiveToolCall(t *testing.T) {
	engine := loadTestEngine(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writer := audit.NewWriter(auditPath)
	cs := setupWrap(t, engine, writer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &gosdk.CallToolParams{Name: "delete_all"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected the destructive tool call to be denied (no TTY in test => deny-by-default), got: %+v", result)
	}

	events, err := audit.ReadAll(auditPath, audit.Filter{Channel: event.ChannelMCP})
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected exactly one mcp-channel audit event, got %d", len(events))
	}
	if events[0].Target != "delete_all" {
		t.Fatalf("expected the audit event's target to be the tool name, got %q", events[0].Target)
	}
	if events[0].Decision.PolicyID != "mcp.destructive_tool_call" {
		t.Fatalf("expected rule mcp.destructive_tool_call, got %q", events[0].Decision.PolicyID)
	}
}

// TestResolvePrompt_NotifiesWhenPersistIsRequestedButUnsupported is a
// regression test for a real honesty gap found via code review: the shared
// TTY prompt advertises "[A] Always allow"/"[D] Always deny" to MCP callers
// too (it's the same Prompter used for CLI), but MCP tool-call persistence
// isn't implemented in V1 — before this fix, choosing "A" silently behaved
// like "allow once" with no indication the user's actual choice was
// discarded.
func TestResolvePrompt_NotifiesWhenPersistIsRequestedButUnsupported(t *testing.T) {
	orig := newTTYPrompter
	defer func() { newTTYPrompter = orig }()

	var out bytes.Buffer
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		return ui.TTYPrompter{In: strings.NewReader("A\n"), Out: &out}, func() {}, nil
	}

	d := decision.Decision{Verdict: decision.Prompt, PolicyID: "mcp.destructive_tool_call"}
	resolved := resolvePrompt("delete_all {}", d)

	if resolved.Outcome() != decision.Allow {
		t.Fatalf("expected the resolved verdict to be Allow, got %v", resolved.Outcome())
	}
	if !strings.Contains(out.String(), "isn't remembered for MCP tool calls") {
		t.Fatalf("expected a notice that the always-allow choice wasn't persisted, got output:\n%s", out.String())
	}
}

func TestResolvePrompt_NoNoticeForOnceChoices(t *testing.T) {
	orig := newTTYPrompter
	defer func() { newTTYPrompter = orig }()

	var out bytes.Buffer
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		return ui.TTYPrompter{In: strings.NewReader("a\n"), Out: &out}, func() {}, nil
	}

	d := decision.Decision{Verdict: decision.Prompt}
	resolvePrompt("read_thing {}", d)

	if strings.Contains(out.String(), "isn't remembered") {
		t.Fatalf("did not expect a persistence notice for a plain 'allow once' choice, got:\n%s", out.String())
	}
}

func TestResolvePrompt_NoTTYDefaultsToDeny(t *testing.T) {
	orig := newTTYPrompter
	defer func() { newTTYPrompter = orig }()
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		return nil, nil, io.ErrClosedPipe
	}

	d := decision.Decision{Verdict: decision.Prompt}
	resolved := resolvePrompt("delete_all {}", d)
	if resolved.Outcome() != decision.Deny {
		t.Fatalf("expected deny-by-default when no controlling terminal is available, got %v", resolved.Outcome())
	}
}

// TestWrap_CrossChannelAuditWithCLI proves the actual product claim: a CLI
// event and an MCP event land in the exact same audit file, distinguishable
// only by Channel — see features/mcp_tool_governance.feature "CLI and MCP
// events land in the same audit log".
func TestWrap_CrossChannelAuditWithCLI(t *testing.T) {
	engine := loadTestEngine(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writer := audit.NewWriter(auditPath)

	// Simulate a CLI-channel event the same way cli/adapter/hook does.
	cliDecision := decision.Decision{Verdict: decision.Prompt, PolicyID: "destructive.rm_rf_protected"}
	cliDecision.Resolve(decision.Deny)
	cliEvent := event.New(event.NewID(), "s1", "claude-code", event.ChannelCLI, event.ActionShellExec, "rm -rf ~/", "rm -rf ~/", cliDecision)
	if err := writer.Append(cliEvent); err != nil {
		t.Fatalf("appending cli event: %v", err)
	}

	cs := setupWrap(t, engine, writer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cs.CallTool(ctx, &gosdk.CallToolParams{Name: "delete_all"}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	all, err := audit.ReadAll(auditPath, audit.Filter{})
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 events total (1 cli + 1 mcp), got %d", len(all))
	}

	cliOnly, _ := audit.ReadAll(auditPath, audit.Filter{Channel: event.ChannelCLI})
	mcpOnly, _ := audit.ReadAll(auditPath, audit.Filter{Channel: event.ChannelMCP})
	if len(cliOnly) != 1 || len(mcpOnly) != 1 {
		t.Fatalf("expected exactly 1 cli event and 1 mcp event, got %d cli, %d mcp", len(cliOnly), len(mcpOnly))
	}
}

// TestSessionIDOf_NeverEmpty is a permanent regression test: a stdio-based
// ServerSession's ID() returns "" (only transports like Streamable HTTP
// assign a real session ID), and core/event.ActionEvent requires a
// non-empty SessionID. Before this fallback existed, that combination made
// every single MCP audit write fail validation and get silently discarded —
// caught by manually running `damping mcp wrap` end-to-end against a real
// subprocess and finding the audit log emptier than it should have been,
// not by any unit test in isolation.
func TestSessionIDOf_NeverEmpty(t *testing.T) {
	if got := sessionIDOf(nil); got == "" {
		t.Fatal("expected a non-empty fallback session id for a nil session")
	}
}

// factsFromCall/toolTags are exercised indirectly above via the real SDK
// types, but the destructive-vs-not distinction is worth pinning down
// directly too, since it's the one place this package diverges from the
// raw MCP spec's own implied default (see the comment on toolTags).
func TestToolTags_OnlyExplicitDestructiveHintIsTagged(t *testing.T) {
	unannotated := &gosdk.Tool{Name: "mystery_tool"}
	tags := toolTags(unannotated)
	for _, tag := range tags {
		if tag == "destructive" {
			t.Fatal("expected an unannotated tool to NOT be tagged destructive (avoids nagging on servers that don't bother annotating)")
		}
	}

	destructive := &gosdk.Tool{Name: "nuke", Annotations: &gosdk.ToolAnnotations{DestructiveHint: boolPtr(true)}}
	tags = toolTags(destructive)
	found := false
	for _, tag := range tags {
		if tag == "destructive" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected an explicit destructiveHint:true to be tagged destructive")
	}
}

func TestRawCallSummary_EmptyArgsOmitted(t *testing.T) {
	if got := rawCallSummary("foo", nil); got != "foo" {
		t.Fatalf("expected bare tool name for no args, got %q", got)
	}
	if got := rawCallSummary("foo", json.RawMessage(`{"a":1}`)); got != `foo {"a":1}` {
		t.Fatalf("expected tool name + args, got %q", got)
	}
}
