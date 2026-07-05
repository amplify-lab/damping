// Package policy is the V1 Go-native rule evaluator. Its Evaluate() call
// signature is deliberately stable so Phase 3's swap to an embedded
// OPA/Rego evaluator (see docs/00-統一開發計畫（定案版）.md §四) is a
// drop-in replacement behind the same interface, not a rewrite of call
// sites in cli/adapter/hook or cli/adapter/mcp.
package policy

import (
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

// Facts is the normalized input an adapter compiles its parsed action into
// before calling Evaluate. This is the shared "language" every transport
// speaks so the policy engine never needs to know about shell ASTs or MCP
// wire formats directly — cli/shell walks a shell AST and produces Facts;
// cli/adapter/mcp inspects a tool call and produces Facts.
type Facts struct {
	Channel    event.Channel
	ActionType event.ActionType

	// Raw is the original command string or tool-call payload, used for
	// always-allow/always-deny pattern matching and for rules that need
	// whole-string context (e.g. known /proc bypass path literals).
	Raw string

	// Command is the primary command name ("rm", "git", "chmod") for shell
	// actions, or the MCP tool name for tool calls.
	Command string
	Args    []string

	// Target is the path, tool name, or URL the action operates on.
	Target string

	// Domain is populated for network-fetching commands (curl/wget) with the
	// source domain, so install-pipeline rules can check it against the
	// allowlist.
	Domain string

	// IsPipeline and PipelineCmds describe a shell pipeline's command names
	// in order (e.g. ["curl", "base64", "sh"]) for pipeline-shape rules.
	IsPipeline   bool
	PipelineCmds []string

	// ToolTags carries MCP tool metadata, e.g. "write", used by identity-
	// bound authorization rules.
	ToolTags []string

	// HasIdentity is true once an action's actor has a bound enterprise
	// identity (always false in the individual tier — see
	// docs/architecture.md §3 on ActionEvent.Identity).
	HasIdentity bool
}

// Engine evaluates Facts against a loaded Config.
type Engine struct {
	cfg Config
}

// New constructs an Engine from an already-loaded, already-validated Config.
func New(cfg Config) *Engine {
	return &Engine{cfg: cfg}
}

// Evaluate returns the Decision for the given Facts. Always-deny patterns are
// checked before always-allow patterns, so a broad user-set allow pattern can
// never silently swallow a narrower, more specific deny — see
// features/self_protection.feature.
func (e *Engine) Evaluate(f Facts) decision.Decision {
	if matchesAnyPattern(e.cfg.AlwaysDeny, f) {
		return decision.Decision{
			Verdict: decision.Deny,
			Reason:  "matched an always-deny pattern",
		}
	}
	if matchesAnyPattern(e.cfg.AlwaysAllow, f) {
		return decision.Decision{
			Verdict: decision.Allow,
			Reason:  "matched an always-allow pattern",
		}
	}

	for _, rc := range e.cfg.Rules {
		m, ok := matchers[rc.ID]
		if !ok {
			// Config.Validate() should have already rejected this, but
			// Evaluate defends independently in case a Config was
			// constructed without going through ParseConfig/LoadConfig.
			continue
		}
		if m(f, e.cfg) {
			return decision.Decision{
				Verdict:  rc.Action,
				PolicyID: rc.ID,
				Reason:   rc.Description,
			}
		}
	}
	return decision.Decision{Verdict: decision.Allow}
}
