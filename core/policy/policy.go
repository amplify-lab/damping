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
//
// JSON tags exist so opa.go can marshal Facts as-is into the OPA `input`
// document — the Go-native and OPA-backed evaluators consume the exact same
// Facts value, which is what makes the OPA swap a true drop-in replacement
// rather than a parallel reimplementation with its own input shape.
type Facts struct {
	Channel    event.Channel    `json:"channel"`
	ActionType event.ActionType `json:"action_type"`

	// Raw is the original command string or tool-call payload, used for
	// always-allow/always-deny pattern matching and for rules that need
	// whole-string context (e.g. known /proc bypass path literals).
	Raw string `json:"raw"`

	// Command is the primary command name ("rm", "git", "chmod") for shell
	// actions, or the MCP tool name for tool calls.
	Command string   `json:"command"`
	Args    []string `json:"args"`

	// Target is the path, tool name, or URL the action operates on.
	Target string `json:"target"`

	// Domain is populated for network-fetching commands (curl/wget) with the
	// source domain, so install-pipeline rules can check it against the
	// allowlist.
	Domain string `json:"domain"`

	// IsPipeline and PipelineCmds describe a shell pipeline's command names
	// in order (e.g. ["curl", "base64", "sh"]) for pipeline-shape rules.
	IsPipeline   bool     `json:"is_pipeline"`
	PipelineCmds []string `json:"pipeline_cmds"`

	// ToolTags carries MCP tool metadata, e.g. "write", used by identity-
	// bound authorization rules.
	ToolTags []string `json:"tool_tags"`

	// HasIdentity is true once an action's actor has a bound enterprise
	// identity (always false in the individual tier — see
	// docs/architecture.md §3 on ActionEvent.Identity).
	HasIdentity bool `json:"has_identity"`
}

// Evaluator is anything that can judge Facts against a policy and return a
// Decision. The Go-native Engine (this file) and the OPA-backed OPAEngine
// (opa.go) both implement it — callers (cli/adapter/hook, cli/adapter/mcp,
// cli/cmd) take this interface, not a concrete *Engine, so swapping which
// evaluator backs a given deployment is a one-line change at construction
// time, never a call-site rewrite. See docs/architecture.md §4.
type Evaluator interface {
	Evaluate(f Facts) decision.Decision
}

// Engine evaluates Facts against a loaded Config.
type Engine struct {
	cfg Config
}

var _ Evaluator = (*Engine)(nil)

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
