package policy

import "github.com/amplify-lab/damping/core/event"

// matchMCPWriteToolUnscopedIdentity is registered but NOT included in
// cli/policies/default.yaml's active rule list — see docs/threat-model.md
// and docs/cli-reference.md §13. The individual tier has no identity system
// at all (ActionEvent.Identity is always empty pre-Phase 5), so this rule
// would fire on nearly every non-explicitly-read-only MCP tool call,
// turning `damping mcp wrap` into a constant nag — exactly the false-
// positive failure mode the project treats as enemy #1. It stays
// implemented and enterprise policy configs (Phase 5) can add it back once
// real identity binding exists to make "unscoped" a meaningful signal.
func matchMCPWriteToolUnscopedIdentity(f Facts, _ Config) bool {
	if f.ActionType != event.ActionToolCall {
		return false
	}
	if !hasTag(f.ToolTags, "write") {
		return false
	}
	return !f.HasIdentity
}

// matchMCPDestructiveToolCall is the individual-tier-appropriate MCP rule:
// it fires when the *server itself* declared a tool destructive (MCP's
// standard ToolAnnotations.DestructiveHint), which needs no identity system
// to be meaningful — see cli/adapter/mcp's tagging logic.
func matchMCPDestructiveToolCall(f Facts, _ Config) bool {
	if f.ActionType != event.ActionToolCall {
		return false
	}
	return hasTag(f.ToolTags, "destructive")
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
