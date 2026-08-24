package hook

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

// MCPToolNamePrefix is how Claude Code (and every agent that copies its
// tool-naming convention) namespaces an MCP tool call in a PreToolUse
// payload: "mcp__<server>__<tool>".
const MCPToolNamePrefix = "mcp__"

// IsMCPToolName reports whether a PreToolUse tool_name is an MCP tool call
// rather than one of the agent's own built-in tools.
func IsMCPToolName(toolName string) bool {
	return strings.HasPrefix(toolName, MCPToolNamePrefix)
}

// MCPToolAnnotations carries the two MCP ToolAnnotations fields the policy
// engine actually consumes. Nothing in any agent's hook contract sends
// these — the agent forwards only tool_name and tool_input — so they can
// only ever arrive as Damping's own optional extension field, from an
// embedding host that already holds the server's tool list. Both fields are
// pointers so "the host said false" stays distinguishable from "the host
// said nothing", which is the whole difference between an explicit
// annotation and an absent one.
type MCPToolAnnotations struct {
	DestructiveHint *bool `json:"destructiveHint"`
	ReadOnlyHint    *bool `json:"readOnlyHint"`
}

// FactsFromMCPToolCall builds Facts for an MCP tool call intercepted on the
// PreToolUse hook channel — the third Facts-producing path in this adapter,
// alongside EvaluateCommand's shell AST and FactsFromToolWrite's file
// writes.
//
// Why this channel needs to exist at all when `damping mcp wrap` already
// governs MCP: wrap is a stdio proxy, so it can only sit in front of a
// server the agent launches as a subprocess. An HTTP/SSE MCP server is
// completely out of its reach — but the agent's own PreToolUse hook still
// fires for those calls. Before this, they fell through cli/cmd/hook.go's
// tool-name switch as "not a tool call Damping's CLI adapter judges", so
// the one channel that could see them ignored them.
//
// The Facts produced here are deliberately the same shape cli/adapter/mcp's
// factsFromCall produces for the wrap channel (same Channel, ActionType,
// Command, and "<tool name> <args json>" Raw), so a rule written for one
// channel behaves identically on the other, and an always-allow pattern
// persisted from either matches the same call arriving through the other.
// The one unavoidable difference is annotations: wrap reads them off the
// server's own tool list, while here they exist only if the host passed
// them (hence the ann parameter, and hence
// core/policy.matchMCPDestructiveToolName as the annotation-free fallback).
func FactsFromMCPToolCall(toolName string, args json.RawMessage, ann *MCPToolAnnotations) policy.Facts {
	compact := compactJSON(args)
	raw := toolName
	if compact != "" {
		raw = toolName + " " + compact
	}
	return policy.Facts{
		Channel:     event.ChannelMCP,
		ActionType:  event.ActionToolCall,
		Raw:         raw,
		Command:     toolName,
		Target:      mcpCallTarget(toolName, args),
		ToolTags:    mcpToolTags(ann),
		HasIdentity: false, // individual tier; Phase 5 wires real AD/LDAP-bound identity
	}
}

// BuildToolCallActionEvent is BuildActionEvent's counterpart for an MCP tool
// call intercepted on the hook channel. It records event.ChannelMCP, not
// ChannelCLI: the transport Damping happened to learn about the call
// through is an implementation detail of which agent is running, while
// "this was an MCP tool call" is the thing a human reading the audit trail
// — or `damping log --channel mcp` — is actually asking about. An identical
// call reaching Damping through `damping mcp wrap` lands on the same
// channel with the same shape, which is the point.
func BuildToolCallActionEvent(eventID, sessionID, actor, target, raw string, d decision.Decision) event.ActionEvent {
	return event.New(eventID, sessionID, actor, event.ChannelMCP, event.ActionToolCall, target, raw, d)
}

// mcpToolTags mirrors cli/adapter/mcp's toolTags for a host-supplied
// annotation set, including its deliberate conservatism about
// "destructive": only an EXPLICIT destructiveHint:true earns the tag, never
// the MCP spec's assume-destructive default for unannotated tools.
//
// A tool with no annotations at all is tagged "write" for the same reason
// wrap tags it that way — readOnlyHint's absence is not a claim of
// read-only — and that tag feeds only the Phase 5 identity rule, which is
// not in the shipped default policy.
func mcpToolTags(ann *MCPToolAnnotations) []string {
	var tags []string
	if ann != nil && ann.DestructiveHint != nil && *ann.DestructiveHint {
		tags = append(tags, "destructive")
	}
	if ann != nil && ann.ReadOnlyHint != nil && *ann.ReadOnlyHint {
		tags = append(tags, "read")
	} else {
		tags = append(tags, "write")
	}
	return tags
}

// mcpCallTargetKeys are the argument names that, in practice, name the thing
// an MCP tool operates on. There is no standard for this — MCP tool schemas
// are free-form — so this is a best-effort read of the common conventions,
// ordered most-specific-first, and it only affects what the audit record and
// the confirmation prompt *show* a human. No rule matches on Facts.Target
// for a tool call (the path/protected-directory rules all gate on a shell
// command first), so a miss here degrades legibility, never enforcement.
var mcpCallTargetKeys = []string{
	"file_path", "filePath",
	"target_path", "targetPath",
	"path", "paths",
	"uri", "url",
	"resource", "target",
	"key", "token",
	"table", "collection",
	"name", "id",
}

func mcpCallTarget(toolName string, args json.RawMessage) string {
	var decoded map[string]any
	if len(args) == 0 || json.Unmarshal(args, &decoded) != nil {
		return toolName
	}
	for _, k := range mcpCallTargetKeys {
		if s, ok := scalarString(decoded[k]); ok {
			return s
		}
	}
	return toolName
}

// scalarString accepts the JSON shapes a "which thing" argument realistically
// takes: a string, or a non-empty array whose first element is a string
// (e.g. {"paths": ["a.md", "b.md"]}). Anything else — a number, an object, a
// nested structure — is left to Facts.Raw, which carries the full argument
// JSON regardless.
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return "", false
		}
		return t, true
	case []any:
		if len(t) == 0 {
			return "", false
		}
		s, ok := t[0].(string)
		return s, ok && s != ""
	}
	return "", false
}

// compactJSON normalizes the host's tool_input formatting away, so the same
// call always produces the same Facts.Raw no matter how the host serialized
// it — which is what makes an [A]/[D] "always" pattern persisted for one
// call actually match the next identical one. Invalid JSON is passed
// through verbatim rather than dropped: it still belongs in the audit
// record and in front of a human at the prompt.
func compactJSON(args json.RawMessage) string {
	trimmed := bytes.TrimSpace(args)
	if len(trimmed) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, trimmed); err != nil {
		return string(trimmed)
	}
	return buf.String()
}
