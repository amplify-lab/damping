package policy

import (
	"strings"
	"unicode"

	"github.com/amplify-lab/damping/core/event"
)

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

// destructiveToolNameVerbs are verbs whose presence as a whole word in an
// MCP tool's own name means the server named the destruction itself. This
// is a deliberately narrower claim than "unannotated, therefore suspect":
// cli/adapter/mcp/facts.go's toolTags rejects the MCP spec's own
// assume-destructive default precisely because almost no real server sets
// ToolAnnotations, so that default would flag nearly every tool call and
// turn Damping into a nag. A tool called "delete_file" is different — the
// server wrote the verb.
//
// Kept to verbs that destroy or revoke, not ones that merely write:
// "update", "set", "write", and "create" are the everyday shape of an
// agent doing its job. "reset" is deliberately excluded too — its most
// common real-world tool names ("reset_password", "reset_filters") are
// nothing like a wipe.
var destructiveToolNameVerbs = map[string]bool{
	"delete":   true,
	"destroy":  true,
	"drop":     true,
	"erase":    true,
	"purge":    true,
	"prune":    true,
	"remove":   true,
	"revoke":   true,
	"rm":       true,
	"truncate": true,
	"unlink":   true,
	"wipe":     true,
}

// matchMCPDestructiveToolName is matchMCPDestructiveToolCall's counterpart
// for the (overwhelmingly common) case where a server ships no
// ToolAnnotations at all, and for the PreToolUse hook channel, whose wire
// format carries no annotations even when the server does declare them —
// see cli/adapter/hook.FactsFromMCPToolCall.
//
// An explicit read-only annotation always wins: the server is the authority
// on its own tools, so a tool it declared read-only is never flagged on the
// strength of how it happens to be named ("delete_dry_run").
func matchMCPDestructiveToolName(f Facts, _ Config) bool {
	if f.ActionType != event.ActionToolCall {
		return false
	}
	if hasTag(f.ToolTags, "read") {
		return false
	}
	for _, w := range toolNameWords(f.Command) {
		if destructiveToolNameVerbs[w] {
			return true
		}
	}
	return false
}

// toolNameWords splits an MCP tool name into lowercase words, at both
// non-alphanumeric separators and camelCase boundaries, so every naming
// convention a real server might use resolves to the same word list:
// "mcp__notes__delete_file", "filesystem.delete_all", and "deleteFile" all
// yield a "delete" word.
//
// Whole words, never substrings — matching "delete" anywhere in the raw
// name would flag "list_deleted_branches", whose call deletes nothing. That
// is the false-positive direction this rule cannot afford (see
// features/mcp_tool_governance.feature).
//
// Kept in lockstep with policy.rego's mcp_tool_name_words — the two
// engines' equivalence is asserted by opa_equivalence_test.go.
func toolNameWords(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case !isToolNameWordRune(r):
			flush()
		case unicode.IsUpper(r) && i > 0 && startsNewCamelWord(runes, i):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return words
}

func isToolNameWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// startsNewCamelWord reports whether the upper-case rune at index i begins a
// new word: either it follows a lower-case letter or digit ("deleteFile"),
// or it is the last capital of an acronym run immediately followed by a
// lower-case letter ("HTTPDelete" -> "http", "delete").
func startsNewCamelWord(runes []rune, i int) bool {
	prev := runes[i-1]
	if unicode.IsLower(prev) || unicode.IsDigit(prev) {
		return true
	}
	return unicode.IsUpper(prev) && i+1 < len(runes) && unicode.IsLower(runes[i+1])
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
