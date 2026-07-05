package mcp

import (
	"encoding/json"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

// factsFromCall normalizes a discovered tool + an incoming call request into
// policy.Facts — the same "language" cli/shell speaks for CLI commands (see
// docs/architecture.md §3).
func factsFromCall(tool *gosdk.Tool, req *gosdk.CallToolRequest) policy.Facts {
	raw := rawCallSummary(tool.Name, req.Params.Arguments)
	return policy.Facts{
		Channel:     event.ChannelMCP,
		ActionType:  event.ActionToolCall,
		Raw:         raw,
		Command:     tool.Name,
		Target:      tool.Name,
		ToolTags:    toolTags(tool),
		HasIdentity: false, // individual tier; Phase 5 wires real AD/LDAP-bound identity
	}
}

func rawCallSummary(toolName string, args json.RawMessage) string {
	if len(args) == 0 {
		return toolName
	}
	return toolName + " " + string(args)
}

// toolTags derives policy tags from MCP's standard ToolAnnotations.
// Deliberately conservative about "destructive": only an EXPLICIT
// destructiveHint:true is tagged, even though the MCP spec's own default
// (absent any annotation) is arguably "assume destructive". Defaulting to
// that spec-implied assumption would flag nearly every unannotated tool —
// most real-world servers don't bother setting this hint — which is
// exactly the constant-nag failure mode this design avoids elsewhere (see
// core/policy/rules_mcp.go's comment on why mcp.write_tool_unscoped_identity
// isn't active by default either).
func toolTags(tool *gosdk.Tool) []string {
	var tags []string
	if tool.Annotations != nil && tool.Annotations.DestructiveHint != nil && *tool.Annotations.DestructiveHint {
		tags = append(tags, "destructive")
	}
	if tool.Annotations != nil && tool.Annotations.ReadOnlyHint {
		tags = append(tags, "read")
	} else {
		tags = append(tags, "write")
	}
	return tags
}
