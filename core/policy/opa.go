package policy

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/open-policy-agent/opa/rego"

	"github.com/amplify-lab/damping/core/decision"
)

//go:embed policy.rego
var policyModule string

// OPAEngine is the OPA/Rego-backed Evaluator — see docs/00-統一開發計畫（定案版）.md
// §四 for why Phase 3 introduces this alongside (not instead of) the
// Go-native Engine: enterprise/Gateway deployments want real policy-as-code
// they can audit and extend without a Go recompile, while the individual-
// tier CLI keeps shipping the lighter, dependency-free Engine by default.
// Both satisfy Evaluator identically — core/policy/opa_equivalence_test.go
// proves they return the same Decision for the exact same test table
// policy_test.go/rules_shell_test.go run against the Go-native Engine.
//
// The actual per-rule detection logic lives in policy.rego (embedded at
// build time); OPAEngine itself only does two things Rego is a poor fit
// for: the always_allow/always_deny override tier (simple user-authored
// glob matching — reusing patterns.go keeps it byte-for-byte identical
// between engines rather than a second implementation to keep in sync), and
// resolving *which* rule wins when policy.rego's `matches` set contains more
// than one id, by walking cfg.Rules in the same order Engine.Evaluate does.
type OPAEngine struct {
	cfg   Config
	query rego.PreparedEvalQuery
}

var _ Evaluator = (*OPAEngine)(nil)

// NewEvaluator constructs the Evaluator cfg.Engine selects. This is the one
// place a caller needs to go through to make Phase 3's OPA/Rego backend
// reachable at all — cli/cmd/hook.go, cli/cmd/mcp.go, and `damping policy
// test` all call this instead of picking an engine type directly, so which
// backend a deployment runs is a policy.yaml setting, never a rebuild.
//
// Compiling the embedded Rego module (NewOPA) costs low-single-digit
// milliseconds. A long-lived process (`damping mcp wrap`) pays that once;
// the one-shot `damping hook pretooluse` subprocess pays it on every single
// invocation, since nothing persists between hook calls. EngineOPA is still
// well inside the "sub-millisecond per Evaluate call" budget
// opa_bench_test.go gates — this cost is startup, not eval — but it is a
// real, deliberate tradeoff: EngineNative has no such cost at all, which is
// why it stays the default.
func NewEvaluator(ctx context.Context, cfg Config) (Evaluator, error) {
	switch cfg.Engine {
	case "", EngineNative:
		return New(cfg), nil
	case EngineOPA:
		return NewOPA(ctx, cfg)
	default:
		return nil, fmt.Errorf("policy: unknown engine %q (want %q or %q)", cfg.Engine, EngineNative, EngineOPA)
	}
}

// NewOPA compiles the embedded Rego policy once so Evaluate never re-parses
// or re-compiles it per call.
func NewOPA(ctx context.Context, cfg Config) (*OPAEngine, error) {
	query, err := rego.New(
		rego.Query("data.damping.policy.matches"),
		rego.Module("policy.rego", policyModule),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: compiling embedded Rego module: %w", err)
	}
	return &OPAEngine{cfg: cfg, query: query}, nil
}

// Evaluate mirrors Engine.Evaluate's shape exactly: always-deny before
// always-allow before rules, so a broad user-set allow pattern can never
// silently swallow a narrower, more specific deny.
func (e *OPAEngine) Evaluate(f Facts) decision.Decision {
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

	matched, err := e.matchingRuleIDs(f)
	if err != nil {
		// PrepareForEval already validated the module at construction time,
		// so a runtime Eval error here means something unexpected (e.g. a
		// value OPA's json round-trip can't represent) — fail open but
		// loud, exactly the convention cli/cmd/hook.go's logDegraded /
		// degradedEvent use for every other internal-failure path. See
		// docs/threat-model.md §6: protection failing silently is worse
		// than protection failing loudly.
		return decision.Decision{
			Verdict:  decision.Allow,
			Degraded: true,
			Reason:   fmt.Sprintf("policy: OPA evaluation failed: %v", err),
		}
	}

	for _, rc := range e.cfg.Rules {
		if !matched[rc.ID] {
			continue
		}
		return decision.Decision{
			Verdict:  rc.Action,
			PolicyID: rc.ID,
			Reason:   rc.Description,
		}
	}
	return decision.Decision{Verdict: decision.Allow}
}

// matchingRuleIDs evaluates policy.rego's `matches` set for f against e.cfg,
// returning it as a lookup set. An empty ResultSet means the query was
// undefined (no rule body matched at all), not an error — the empty map
// returned in that case is exactly the right zero value for the caller's
// membership checks.
func (e *OPAEngine) matchingRuleIDs(f Facts) (map[string]bool, error) {
	input := map[string]any{
		"facts": map[string]any{
			"channel":       f.Channel,
			"action_type":   f.ActionType,
			"raw":           f.Raw,
			"command":       f.Command,
			"args":          orEmpty(f.Args),
			"target":        f.Target,
			"domain":        f.Domain,
			"is_pipeline":   f.IsPipeline,
			"pipeline_cmds": orEmpty(f.PipelineCmds),
			"tool_tags":     orEmpty(f.ToolTags),
			"has_identity":  f.HasIdentity,
		},
		"config": map[string]any{
			"protected_paths":             orEmpty(e.cfg.ProtectedPaths),
			"allowlisted_install_domains": orEmpty(e.cfg.AllowlistedInstallDomains),
		},
	}

	rs, err := e.query.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return map[string]bool{}, nil
	}

	raw, ok := rs[0].Expressions[0].Value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected result shape for data.damping.policy.matches: %T", rs[0].Expressions[0].Value)
	}
	ids := make(map[string]bool, len(raw))
	for _, v := range raw {
		id, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected element type in matches set: %T", v)
		}
		ids[id] = true
	}
	return ids, nil
}

// orEmpty guarantees a non-nil slice so it marshals to JSON `[]` rather than
// `null` — Rego's `some x in y` over a null value in the OPA input document
// would make every rule that iterates that field simply never match rather
// than erroring, which is functionally fine but relies on that lenient
// behavior rather than stating the contract explicitly.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
