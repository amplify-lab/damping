package policy

import (
	"fmt"
	"os"

	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
	"gopkg.in/yaml.v3"
)

// Config is the on-disk shape of ~/.damping/policy.yaml. See
// docs/cli-reference.md §13 for the full documented schema. This struct is
// the *behavioral* contract (which rules are active, at what risk/action) —
// the actual detection logic per rule lives in the hardcoded matcher
// registry in rules.go for V1, and swaps to OPA/Rego in Phase 3 behind the
// same Evaluate() call site (see docs/architecture.md §4).
type Config struct {
	Version int `yaml:"version"`

	// Engine selects which Evaluator implementation NewEvaluator constructs
	// for this Config: EngineNative (the default when empty — zero extra
	// dependencies, the right choice for the individual-tier CLI) or
	// EngineOPA (embedded OPA/Rego — see docs/architecture.md §4 for when
	// Phase 3's Gateway/enterprise deployments should prefer it instead).
	Engine string `yaml:"engine,omitempty"`

	ProtectedPaths            []string `yaml:"protected_paths"`
	AllowlistedInstallDomains []string `yaml:"allowlisted_install_domains"`
	// AllowlistedEgressDomains is checked by destructive.secret_exfiltration
	// — deliberately a separate list from AllowlistedInstallDomains, since
	// "safe to install from" and "safe to send local file contents to" are
	// different trust decisions a user may want to configure independently.
	AllowlistedEgressDomains []string     `yaml:"allowlisted_egress_domains"`
	Rules                    []RuleConfig `yaml:"rules"`
	AlwaysAllow              []string     `yaml:"always_allow"`
	AlwaysDeny               []string     `yaml:"always_deny"`

	// NonInteractivePromptFallback lets an operator resolve a Prompt-tier
	// decision by risk tier when no controlling terminal is available to ask
	// a human (e.g. an agent running unattended in the background) — see
	// cli/cmd/hook.go's resolveNonInteractivePrompt. Absent, or a risk tier
	// with no entry here, keeps the original conservative default: deny.
	// Values must be "allow" or "deny" (never "prompt" — there's no human to
	// re-ask), enforced by Validate.
	NonInteractivePromptFallback map[event.RiskLevel]decision.Verdict `yaml:"noninteractive_prompt_fallback,omitempty"`

	// UILanguage is the operator's preferred display language for the two
	// places this binary renders human-facing text directly rather than
	// just logging it: the TTY confirmation prompt (cli/ui) and `damping
	// policy test`'s output. Recognized values: "" (unset — the renderer
	// auto-detects from $LANG/$LC_ALL at render time, defaulting to
	// English) or "zh-TW". `damping init` resolves and writes this once,
	// interactively or via --lang (see core/policy.SetUILanguage, which
	// edits an existing file in place without disturbing anything else in
	// it).
	//
	// This is a display/rendering preference, not a policy-matching
	// concern — it deliberately lives in this Config rather than a
	// separate settings file only because `damping init` already owns
	// writing/updating this one file. It does NOT affect Decision.Reason,
	// the audit log, or compliance reports, which stay English always:
	// core/policy/opa_equivalence_test.go's byte-identical-Reason
	// assertion, core/compliance's report formatting, and every existing
	// consumer of ActionEvent already depend on Reason being a single
	// canonical English string. Translation happens only in cli/i18n, at
	// the last-mile render step in cli/ui and cli/cmd/policy.go — this
	// field is merely the stored preference those call sites consult.
	UILanguage string `yaml:"ui_language,omitempty"`
}

// EngineNative and EngineOPA are the recognized values for Config.Engine.
const (
	EngineNative = "native"
	EngineOPA    = "opa"
)

// RuleConfig describes one policy rule's identity and default disposition.
// JSON tags exist so the local dashboard's /api/policy endpoint can
// marshal a Config's Rules directly — see cli/dashboard/handlers.go's
// handlePolicy — without a second, parallel struct to keep in sync.
type RuleConfig struct {
	ID          string           `yaml:"id" json:"id"`
	Description string           `yaml:"description" json:"description"`
	Risk        event.RiskLevel  `yaml:"risk" json:"risk"`
	Action      decision.Verdict `yaml:"action" json:"action"`
}

// LoadConfig reads and parses a policy YAML file from disk.
func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the local user's own policy file (~/.damping default or their own --config flag), not an attacker-influenced path; no cross-trust-boundary traversal risk
	if err != nil {
		return Config{}, fmt.Errorf("policy: reading %s: %w", path, err)
	}
	return ParseConfig(raw)
}

// ParseConfig parses policy YAML from an in-memory buffer — split out from
// LoadConfig so tests and `damping policy validate` can exercise parsing
// without touching the filesystem.
func ParseConfig(raw []byte) (Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("policy: parsing config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate reports schema-level problems: unknown rule ids (no matcher
// registered for them), missing risk/action, etc. This is what
// `damping policy validate` calls before ever loading a file into the live
// engine — see features/policy_config.feature.
func (c Config) Validate() error {
	if c.Version == 0 {
		return fmt.Errorf("policy: missing or zero \"version\" field")
	}
	switch c.Engine {
	case "", EngineNative, EngineOPA:
	default:
		return fmt.Errorf("policy: unknown engine %q (want %q or %q)", c.Engine, EngineNative, EngineOPA)
	}
	seen := make(map[string]bool, len(c.Rules))
	for _, r := range c.Rules {
		if r.ID == "" {
			return fmt.Errorf("policy: rule missing \"id\"")
		}
		if seen[r.ID] {
			return fmt.Errorf("policy: duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if _, ok := matchers[r.ID]; !ok {
			return fmt.Errorf("policy: rule %q has no registered matcher", r.ID)
		}
		switch r.Action {
		case decision.Allow, decision.Deny, decision.Prompt:
		default:
			return fmt.Errorf("policy: rule %q has invalid action %q", r.ID, r.Action)
		}
		switch r.Risk {
		case event.RiskLow, event.RiskMedium, event.RiskHigh, event.RiskCritical:
		default:
			// A rule's Risk flows verbatim into Decision.Risk and then
			// ActionEvent.RiskLevel (see event.New) — an unrecognized value
			// here wouldn't just fail to filter/display correctly, it would
			// silently score as the dashboard's lowest severity (riskScore's
			// default case), the least safe fallback for what a rule author
			// likely meant as a real risk tier. Reject at load time instead.
			return fmt.Errorf("policy: rule %q has invalid risk %q", r.ID, r.Risk)
		}
	}
	for risk, verdict := range c.NonInteractivePromptFallback {
		switch risk {
		case event.RiskLow, event.RiskMedium, event.RiskHigh, event.RiskCritical:
		default:
			return fmt.Errorf("policy: noninteractive_prompt_fallback has invalid risk %q", risk)
		}
		switch verdict {
		case decision.Allow, decision.Deny:
		default:
			return fmt.Errorf("policy: noninteractive_prompt_fallback[%q] has invalid verdict %q (want %q or %q)", risk, verdict, decision.Allow, decision.Deny)
		}
	}
	switch c.UILanguage {
	case "", "en", "zh-TW":
	default:
		// This list is the one place core/policy knows about UI languages —
		// it cannot import cli/i18n (whose Lang constants mirror these same
		// two values) since core and cli are separate Go modules and core
		// can never depend on cli. Keep this switch's cases in sync with
		// cli/i18n.Lang by convention if a language is ever added.
		return fmt.Errorf("policy: unknown ui_language %q (want \"en\" or \"zh-TW\")", c.UILanguage)
	}
	return nil
}
