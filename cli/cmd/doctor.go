package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/adapter/agent"
	"github.com/amplify-lab/damping/cli/paths"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/policy"
)

// doctorState is what we remember between `damping doctor` runs so we can
// notice changes (hook removed, policy tampered with) rather than only ever
// reporting the current instant — see docs/threat-model.md §4 and §8.
type doctorState struct {
	PolicyHash      string `json:"policy_hash"`
	ClaudeHookFound bool   `json:"claude_hook_found"`
	CursorHookFound bool   `json:"cursor_hook_found"`
	CheckedAt       string `json:"checked_at"`
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
			}

			claudePath := paths.ClaudeSettings()
			if hasClaude, err := agent.HasClaudeCodeHook(claudePath); err == nil {
				next.ClaudeHookFound = hasClaude
				switch {
				case prev.ClaudeHookFound && !hasClaude:
					fmt.Fprintln(w, "  ✗ Claude Code hook missing — was it removed outside `damping off`?")
					fmt.Fprintln(w, "      → run `damping init --agent claude-code --force` to reinstall")
					failed++
				case hasClaude:
					fmt.Fprintln(w, "  ✓ Claude Code hook registered")
				default:
					fmt.Fprintln(w, "  · Claude Code hook not registered — run `damping init` if you use Claude Code")
				}
			}

			cursorPath := paths.CursorHooks()
			if hasCursor, err := agent.HasCursorHook(cursorPath); err == nil {
				next.CursorHookFound = hasCursor
				switch {
				case prev.CursorHookFound && !hasCursor:
					fmt.Fprintln(w, "  ✗ Cursor hook missing — was it removed outside `damping off`?")
					fmt.Fprintln(w, "      → run `damping init --agent cursor --force` to reinstall")
					failed++
				case hasCursor:
					fmt.Fprintln(w, "  ✓ Cursor hook registered")
				default:
					fmt.Fprintln(w, "  · Cursor hook not registered — run `damping init` if you use Cursor")
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
