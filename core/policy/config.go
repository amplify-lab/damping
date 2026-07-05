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

	ProtectedPaths            []string     `yaml:"protected_paths"`
	AllowlistedInstallDomains []string     `yaml:"allowlisted_install_domains"`
	Rules                     []RuleConfig `yaml:"rules"`
	AlwaysAllow               []string     `yaml:"always_allow"`
	AlwaysDeny                []string     `yaml:"always_deny"`
}

// EngineNative and EngineOPA are the recognized values for Config.Engine.
const (
	EngineNative = "native"
	EngineOPA    = "opa"
)

// RuleConfig describes one policy rule's identity and default disposition.
type RuleConfig struct {
	ID          string           `yaml:"id"`
	Description string           `yaml:"description"`
	Risk        event.RiskLevel  `yaml:"risk"`
	Action      decision.Verdict `yaml:"action"`
}

// LoadConfig reads and parses a policy YAML file from disk.
func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
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
	}
	return nil
}
