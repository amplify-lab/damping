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

			path, err := resolvePolicyPath()
			if err != nil {
				return err
			}
			cfg, cfgErr := policy.LoadConfig(path)

			// "Damping: ON" here only ever meant "not explicitly disabled
			// via `damping off`" (IsDisabled just checks a marker file) —
			// entirely independent of whether the policy file it's
			// supposed to be enforcing can even be read. Found via a
			// manual UX walkthrough: with an unreadable/invalid policy
			// file, cli/cmd/hook.go's runHook logs a degraded event and
			// returns nil (exit 0) on every CLI shell-command action, which
			// both this project's own hook contract and the real Claude
			// Code/Cursor one treat as "fail open" — while status still
			// proudly said "ON" with the actual problem buried in a
			// secondary Policy: line a skim could miss entirely. Surfacing
			// it on the same headline line a user is most likely to
			// actually read. Scoped to "CLI shell-command", not a blanket
			// "every action": on this identical LoadConfig error,
			// cli/cmd/mcp.go's `mcp wrap` returns the error immediately and
			// never starts wrapping at all — an MCP tool call fails closed
			// (the wrapped server never launches), not open.
			switch {
			case disabled:
				fmt.Fprintln(w, "Damping: OFF")
			case cfgErr != nil:
				fmt.Fprintln(w, "Damping: ON, but NOT protecting you — the policy file failed to load, so every CLI shell-command action fails open (see Policy line below; `damping mcp wrap` instead refuses to start at all on this same error)")
			default:
				fmt.Fprintln(w, "Damping: ON")
			}

			if cfgErr != nil {
				fmt.Fprintf(w, "Policy:  %s (error: %v)\n", path, cfgErr)
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

			// A review found this RunE always returned nil even when the
			// headline just said "NOT protecting you" — `damping doctor`
			// already treats this identical policy.LoadConfig failure as
			// Code:4 (see doctor.go), so a script doing
			// `damping status && deploy` deserves the same non-zero signal,
			// not a silent exit 0 paired with a loud warning nobody's
			// parsing stdout for.
			if !disabled && cfgErr != nil {
				return &ExitCodeError{Code: 4}
			}
			return nil
		},
	}
}
