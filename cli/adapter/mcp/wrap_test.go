package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amplify-lab/damping/cli/paths"
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
func setupWrap(t *testing.T, engine *policy.Engine, policyPath string, writer *audit.Writer) *gosdk.ClientSession {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	upstreamServerSide, upstreamDampingSide := gosdk.NewInMemoryTransports()
	downstreamDampingSide, downstreamClientSide := gosdk.NewInMemoryTransports()

	startFakeRealServer(t, ctx, upstreamServerSide)

	go func() {
		_ = wrapTransport(ctx, upstreamDampingSide, downstreamDampingSide, engine, policyPath, writer, "test-client")
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
	cfg, err := policy.LoadConfig(testPolicyPath(t))
	if err != nil {
		t.Fatalf("loading default policy: %v", err)
	}
	return policy.New(cfg)
}

// testPolicyPath returns a fresh per-test copy of cli/policies/default.yaml
// so tests that persist an always-allow/deny pattern (policy.AppendAlwaysPattern
// requires a real file with always_allow/always_deny sequences to append to)
// never mutate the actual shipped default policy.
func testPolicyPath(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..", "policies", "default.yaml")
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading default policy: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		t.Fatalf("writing test policy copy: %v", err)
	}
	return dst
}

func TestWrap_ForwardsReadOnlyToolCallAndAllows(t *testing.T) {
	engine := loadTestEngine(t)
	writer := audit.NewWriter(filepath.Join(t.TempDir(), "audit.jsonl"))
	cs := setupWrap(t, engine, testPolicyPath(t), writer)

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
	cs := setupWrap(t, engine, testPolicyPath(t), writer)

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

// TestResolvePrompt_PersistsAlwaysAllowChoice is the regression test for a
// real honesty gap found via code review: the shared TTY prompt advertises
// "[A] Always allow"/"[D] Always deny" to MCP callers too (it's the same
// Prompter used for CLI), but MCP tool-call persistence wasn't implemented
// in V1 — choosing "A" silently behaved like "allow once" with no
// indication the user's actual choice was discarded. Now an "A" choice must
// both write the pattern to policyPath AND record it in overlay.
func TestResolvePrompt_PersistsAlwaysAllowChoice(t *testing.T) {
	orig := newTTYPrompter
	defer func() { newTTYPrompter = orig }()

	var out bytes.Buffer
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		return ui.TTYPrompter{In: strings.NewReader("A\n"), Out: &out}, func() {}, nil
	}

	policyPath := testPolicyPath(t)
	overlay := &alwaysOverlay{}
	d := decision.Decision{Verdict: decision.Prompt, PolicyID: "mcp.destructive_tool_call"}
	resolved := resolvePrompt(policyPath, overlay, "delete_all {}", d)

	if resolved.Outcome() != decision.Allow {
		t.Fatalf("expected the resolved verdict to be Allow, got %v", resolved.Outcome())
	}
	if strings.Contains(out.String(), "couldn't save") {
		t.Fatalf("expected no failure notice for a successful persist, got:\n%s", out.String())
	}

	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		t.Fatalf("reloading policy file: %v", err)
	}
	found := false
	for _, p := range cfg.AlwaysAllow {
		if p == "delete_all {}" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected \"delete_all {}\" to be persisted into always_allow, got %v", cfg.AlwaysAllow)
	}

	if v, ok := overlay.verdict("delete_all {}"); !ok || v != decision.Allow {
		t.Fatalf("expected the overlay to also remember this choice for the rest of the session, got %v, %v", v, ok)
	}
}

// TestResolvePrompt_ConcurrentCallsForSameRawOnlyPromptOnce is a regression
// test found via adversarial review: registerForwardingTool's handler checks
// the overlay before ever calling resolvePrompt, so two goroutines racing on
// the exact same not-yet-decided raw call both miss that pre-lock check and
// both reach resolvePrompt, serialized by ttyPromptMu. Without a second
// overlay check right after acquiring the lock, the loser would re-prompt a
// human for a call the winner (just ahead of it) already resolved a moment
// earlier — and could even persist a contradictory answer (e.g. "always
// deny" after the winner just recorded "always allow") for the same raw
// string. go test -race stays clean regardless, since this was a race-free
// but logically wrong sequencing, not a data race — this test asserts the
// actual behavior (exactly one prompt, one consistent outcome), which -race
// alone cannot catch.
func TestResolvePrompt_ConcurrentCallsForSameRawOnlyPromptOnce(t *testing.T) {
	orig := newTTYPrompter
	defer func() { newTTYPrompter = orig }()

	var promptCount int32
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		atomic.AddInt32(&promptCount, 1)
		return ui.TTYPrompter{In: strings.NewReader("A\n"), Out: io.Discard}, func() {}, nil
	}

	policyPath := testPolicyPath(t)
	overlay := &alwaysOverlay{}

	const n = 2
	results := make([]decision.Decision, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = resolvePrompt(policyPath, overlay, "delete_all {}", decision.Decision{Verdict: decision.Prompt})
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt32(&promptCount); got != 1 {
		t.Fatalf("expected exactly one TTY prompt across %d concurrent calls for the same raw, got %d", n, got)
	}
	for i := 1; i < n; i++ {
		if results[i].Outcome() != results[0].Outcome() {
			t.Fatalf("expected every concurrent call to resolve to the same verdict, got %v and %v", results[0].Outcome(), results[i].Outcome())
		}
	}
}

// TestResolvePrompt_FailedPersistNotifiesAndLeavesOverlayUntouched proves the
// failure path stays loud rather than silently pretending the choice was
// remembered when it wasn't actually saved to disk.
func TestResolvePrompt_FailedPersistNotifiesAndLeavesOverlayUntouched(t *testing.T) {
	orig := newTTYPrompter
	defer func() { newTTYPrompter = orig }()

	var out bytes.Buffer
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		return ui.TTYPrompter{In: strings.NewReader("A\n"), Out: &out}, func() {}, nil
	}

	overlay := &alwaysOverlay{}
	d := decision.Decision{Verdict: decision.Prompt}
	resolved := resolvePrompt(filepath.Join(t.TempDir(), "does-not-exist.yaml"), overlay, "delete_all {}", d)

	if resolved.Outcome() != decision.Allow {
		t.Fatalf("expected the resolved verdict to still be Allow even though persisting failed, got %v", resolved.Outcome())
	}
	if !strings.Contains(out.String(), "couldn't save this as an always-allow pattern") {
		t.Fatalf("expected a failure notice, got output:\n%s", out.String())
	}
	if _, ok := overlay.verdict("delete_all {}"); ok {
		t.Fatal("did not expect the overlay to remember a choice that failed to persist to disk")
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
	resolvePrompt(testPolicyPath(t), &alwaysOverlay{}, "read_thing {}", d)

	if strings.Contains(out.String(), "couldn't save") || strings.Contains(out.String(), "isn't remembered") {
		t.Fatalf("did not expect any persistence notice for a plain 'allow once' choice, got:\n%s", out.String())
	}
}

func TestResolvePrompt_NoTTYDefaultsToDeny(t *testing.T) {
	orig := newTTYPrompter
	defer func() { newTTYPrompter = orig }()
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		return nil, nil, io.ErrClosedPipe
	}

	d := decision.Decision{Verdict: decision.Prompt}
	resolved := resolvePrompt(testPolicyPath(t), &alwaysOverlay{}, "delete_all {}", d)
	if resolved.Outcome() != decision.Deny {
		t.Fatalf("expected deny-by-default when no controlling terminal is available, got %v", resolved.Outcome())
	}
}

// TestWrap_PersistsAlwaysAllowChoiceForRestOfSession is the end-to-end BDD
// scenario in features/mcp_tool_governance.feature: choosing "Always allow"
// for one MCP tool call must make every subsequent identical call in the
// *same* `damping mcp wrap` session succeed without prompting again — not
// just on a hypothetical future run. See alwaysOverlay's doc comment for why
// this requires more than writing the pattern to policyPath alone.
func TestWrap_PersistsAlwaysAllowChoiceForRestOfSession(t *testing.T) {
	engine := loadTestEngine(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writer := audit.NewWriter(auditPath)
	cs := setupWrap(t, engine, testPolicyPath(t), writer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	orig := newTTYPrompter
	defer func() { newTTYPrompter = orig }()
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		return ui.TTYPrompter{In: strings.NewReader("A\n"), Out: io.Discard}, func() {}, nil
	}

	result, err := cs.CallTool(ctx, &gosdk.CallToolParams{Name: "delete_all"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected the always-allow resolution to permit the first call, got error result: %+v", result)
	}

	// A second, independent call for the exact same tool+args must now be
	// silently allowed via the in-memory overlay — proven by never invoking
	// the prompter again.
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		t.Fatal("prompter must not be invoked once the exact call is in the always-allow overlay")
		return ui.TTYPrompter{}, func() {}, nil
	}
	result, err = cs.CallTool(ctx, &gosdk.CallToolParams{Name: "delete_all"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected the second identical call to be silently allowed via the overlay, got error result: %+v", result)
	}
}

// TestWrap_PersistsAlwaysDenyChoiceForRestOfSession mirrors
// TestWrap_PersistsAlwaysAllowChoiceForRestOfSession for the "D" (always
// deny) choice — a coverage gap flagged via adversarial review, since only
// the always-allow path had an end-to-end session-level test.
func TestWrap_PersistsAlwaysDenyChoiceForRestOfSession(t *testing.T) {
	engine := loadTestEngine(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writer := audit.NewWriter(auditPath)
	cs := setupWrap(t, engine, testPolicyPath(t), writer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	orig := newTTYPrompter
	defer func() { newTTYPrompter = orig }()
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		return ui.TTYPrompter{In: strings.NewReader("D\n"), Out: io.Discard}, func() {}, nil
	}

	result, err := cs.CallTool(ctx, &gosdk.CallToolParams{Name: "delete_all"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected the always-deny resolution to deny the first call, got: %+v", result)
	}

	// A second, independent call for the exact same tool+args must now be
	// silently denied via the in-memory overlay — proven by never invoking
	// the prompter again.
	newTTYPrompter = func() (ui.Prompter, func(), error) {
		t.Fatal("prompter must not be invoked once the exact call is in the always-deny overlay")
		return ui.TTYPrompter{}, func() {}, nil
	}
	result, err = cs.CallTool(ctx, &gosdk.CallToolParams{Name: "delete_all"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected the second identical call to be silently denied via the overlay, got: %+v", result)
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

	cs := setupWrap(t, engine, testPolicyPath(t), writer)
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

// TestWrap_RespectsOff is a regression test for a real doc/behavior
// mismatch: docs/cli-reference.md §6 says `damping off` means "your agent's
// commands will NOT be checked" with no channel qualifier, but the MCP wrap
// adapter used to never call enforcement.IsDisabled() at all — a destructive
// tool call would still be evaluated (and denied) even while enforcement was
// supposedly off. Checked per-call, not just at Wrap's startup, since this
// process stays alive for the whole MCP session.
func TestWrap_RespectsOff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAMPING_HOME", filepath.Join(dir, "damping-home"))
	marker, err := paths.DisabledMarker()
	if err != nil {
		t.Fatalf("resolving disabled marker path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatalf("creating damping home: %v", err)
	}
	if err := os.WriteFile(marker, []byte(""), 0o600); err != nil {
		t.Fatalf("writing disabled marker: %v", err)
	}

	engine := loadTestEngine(t)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writer := audit.NewWriter(auditPath)
	cs := setupWrap(t, engine, testPolicyPath(t), writer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := cs.CallTool(ctx, &gosdk.CallToolParams{Name: "delete_all"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected a destructive tool call to be forwarded unchecked while enforcement is off, got error result: %+v", result)
	}

	events, err := audit.ReadAll(auditPath, audit.Filter{})
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no audit events while enforcement is off, got %d", len(events))
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
