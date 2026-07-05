package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/adapter/agent"
	"github.com/amplify-lab/damping/core/policy"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether Damping is currently enforcing, and against which policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()

			disabled, err := IsDisabled()
			if err != nil {
				return err
			}
			if disabled {
				fmt.Fprintln(w, "Damping: OFF")
			} else {
				fmt.Fprintln(w, "Damping: ON")
			}

			path, err := resolvePolicyPath()
			if err != nil {
				return err
			}
			cfg, err := policy.LoadConfig(path)
			if err != nil {
				fmt.Fprintf(w, "Policy:  %s (error: %v)\n", path, err)
			} else {
				fmt.Fprintf(w, "Policy:  %s (%d rules)\n", path, len(cfg.Rules))
			}

			// Agent/sync status is independent of whether the policy file
			// loaded — a machine that never ran `damping init` still
			// deserves to see "no agents registered", not nothing at all.
			var agents []string
			if has, err := agent.HasClaudeCodeHook(claudeSettingsPath()); err == nil && has {
				agents = append(agents, "claude-code (active)")
			}
			if has, err := agent.HasCursorHook(cursorHooksPath()); err == nil && has {
				agents = append(agents, "cursor (active)")
			}
			if len(agents) == 0 {
				agents = append(agents, "none registered — run `damping init`")
			}
			fmt.Fprintf(w, "Agents:  %s\n", strings.Join(agents, ", "))
			// Team sync (Phase 4) doesn't exist yet — this line is
			// unconditionally true in V1, not aspirational.
			fmt.Fprintln(w, "Sync:    disabled (individual tier)")
			return nil
		},
	}
}
