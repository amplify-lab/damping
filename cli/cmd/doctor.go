package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/adapter/agent"
	"github.com/amplify-lab/damping/cli/paths"
	"github.com/amplify-lab/damping/cli/policies"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/policy"
)

// doctorState is what we remember between `damping doctor` runs so we can
// notice changes (hook removed, policy tampered with) rather than only ever
// reporting the current instant — see docs/threat-model.md §4 and §8.
type doctorState struct {
	PolicyHash string          `json:"policy_hash"`
	HookFound  map[string]bool `json:"hook_found,omitempty"`
	CheckedAt  string          `json:"checked_at"`

	// Legacy, pre-registry fields (docs/00 §七 item 8) — read-only, only
	// ever populated by unmarshaling an old doctor-state.json written
	// before HookFound existed. loadDoctorState migrates these into
	// HookFound so upgrading doesn't spuriously report "hook missing" for
	// an agent that was already registered; nothing writes them anymore.
	LegacyClaudeHookFound bool `json:"claude_hook_found,omitempty"`
	LegacyCursorHookFound bool `json:"cursor_hook_found,omitempty"`
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the environment: policy validity, hook registration, degraded-mode history",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			fmt.Fprintln(w, "Damping doctor — environment check")
			fmt.Fprintln(w)

			failed, warned := 0, 0
			prev, _ := loadDoctorState()
			next := doctorState{CheckedAt: time.Now().Format(time.RFC3339)}

			policyPath, err := resolvePolicyPath()
			if err != nil {
				return err
			}
			cfg, err := policy.LoadConfig(policyPath)
			if err != nil {
				fmt.Fprintf(w, "  ✗ Policy file invalid (%s): %v\n", policyPath, err)
				failed++
			} else {
				hash := hashFile(policyPath)
				next.PolicyHash = hash
				if prev.PolicyHash != "" && prev.PolicyHash != hash {
					fmt.Fprintf(w, "  ⚠ Policy file hash changed since the last check (%s)\n", policyPath)
					warned++
				} else {
					fmt.Fprintf(w, "  ✓ Policy file valid (%s, %d rules)\n", policyPath, len(cfg.Rules))
				}

				if missing := missingDefaultRules(cfg); len(missing) > 0 {
					fmt.Fprintf(w, "  ⚠ %d rule(s) shipped in the current default policy are missing from your policy file — probably just older than this binary, not a deliberate removal (`damping init` never overwrites an existing policy.yaml, so upgrading the binary alone doesn't add new default rules to it):\n", len(missing))
					for _, id := range missing {
						fmt.Fprintf(w, "      - %s\n", id)
					}
					fmt.Fprintf(w, "      → review, then `damping init --force` to refresh (overwrites the whole file — re-add any custom always_allow/always_deny/protected_paths entries afterward)\n")
					warned++
				}
			}

			next.HookFound = map[string]bool{}
			for _, a := range agent.Registry {
				has, err := a.HasHook(a.ConfigPath())
				if err != nil {
					continue
				}
				next.HookFound[a.Name] = has
				switch {
				case prev.HookFound[a.Name] && !has:
					fmt.Fprintf(w, "  ✗ %s hook missing — was it removed outside `damping off`?\n", a.DisplayName)
					fmt.Fprintf(w, "      → run `damping init --agent %s --force` to reinstall\n", a.Name)
					failed++
				case has:
					fmt.Fprintf(w, "  ✓ %s hook registered\n", a.DisplayName)
				default:
					fmt.Fprintf(w, "  · %s hook not registered — run `damping init` if you use %s\n", a.DisplayName, a.DisplayName)
				}
			}

			auditPath, err := paths.Audit()
			if err == nil {
				degraded, readErr := audit.ReadAll(auditPath, audit.Filter{Outcome: "degraded", Since: time.Now().Add(-7 * 24 * time.Hour)})
				switch {
				case readErr != nil:
					// A prior version discarded this error and fell through
					// to "✓ No degraded-mode events," a false all-clear —
					// found via review. A genuine read/parse failure here
					// means doctor cannot actually vouch for the audit log's
					// health, which is itself worth a warning, not silence.
					fmt.Fprintf(w, "  ⚠ Could not read the audit log to check for degraded-mode events: %v\n", readErr)
					warned++
				case len(degraded) > 0:
					fmt.Fprintf(w, "  ⚠ %d degraded-mode event(s) in the last 7 days — run `damping log --outcome degraded` for details\n", len(degraded))
					warned++
				default:
					fmt.Fprintln(w, "  ✓ No degraded-mode events in the last 7 days")
				}
			}

			_ = saveDoctorState(next)

			fmt.Fprintln(w)
			fmt.Fprintf(w, "%d check(s) failed, %d warning(s).\n", failed, warned)
			if failed > 0 {
				return &ExitCodeError{Code: 4}
			}
			return nil
		},
	}
}

// missingDefaultRules reports which rule ids the binary's own currently-
// embedded default policy (cli/policies.Default) ships that cfg does not
// have — a staleness signal, not a validity one: cfg is already a fully
// valid, loadable Config regardless of this check's result. A parse
// failure on the embedded default (which should never happen in a real
// release — it's covered by core/policy's own TestLoadConfig_
// DefaultPolicyIsValid) fails this check silently rather than crashing
// `damping doctor` over an internal packaging problem it can't fix by
// itself.
func missingDefaultRules(cfg policy.Config) []string {
	defaultCfg, err := policy.ParseConfig([]byte(policies.Default))
	if err != nil {
		return nil
	}
	have := make(map[string]bool, len(cfg.Rules))
	for _, r := range cfg.Rules {
		have[r.ID] = true
	}
	var missing []string
	for _, r := range defaultCfg.Rules {
		if !have[r.ID] {
			missing = append(missing, r.ID)
		}
	}
	sort.Strings(missing)
	return missing
}

func hashFile(path string) string {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the resolved policy file path (default or the user's own --config flag), not an attacker-influenced path
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func loadDoctorState() (doctorState, error) {
	path, err := paths.DoctorState()
	if err != nil {
		return doctorState{}, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is paths.DoctorState()'s fixed ~/.damping/doctor-state.json path (or $DAMPING_HOME override), not an attacker-influenced path
	if err != nil {
		return doctorState{}, nil // no prior state is not an error
	}
	var s doctorState
	_ = json.Unmarshal(data, &s)
	if s.HookFound == nil {
		s.HookFound = map[string]bool{}
	}
	// Migrate a doctor-state.json written before the agent registry
	// existed (see the Legacy* fields' doc comment) so upgrading doesn't
	// spuriously report "hook missing" for an agent already registered.
	if s.LegacyClaudeHookFound {
		s.HookFound["claude-code"] = true
	}
	if s.LegacyCursorHookFound {
		s.HookFound["cursor"] = true
	}
	return s, nil
}

func saveDoctorState(s doctorState) error {
	path, err := paths.DoctorState()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
