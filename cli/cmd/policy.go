package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/adapter/hook"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/policy"
)

func newPolicyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "policy",
		Short: "Inspect and dry-run the active policy",
	}
	c.AddCommand(newPolicyListCmd())
	c.AddCommand(newPolicyTestCmd())
	c.AddCommand(newPolicyValidateCmd())
	return c
}

func newPolicyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every active rule, its risk level, and its default action",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := resolvePolicyPath()
			if err != nil {
				return err
			}
			cfg, err := policy.LoadConfig(path)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-42s %-9s %s\n", "ID", "RISK", "ACTION")
			for _, r := range cfg.Rules {
				fmt.Fprintf(w, "%-42s %-9s %s\n", r.ID, r.Risk, r.Action)
			}
			return nil
		},
	}
}

func newPolicyTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <command>",
		Short: "Dry-run a command against the policy without executing it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := resolvePolicyPath()
			if err != nil {
				return err
			}
			cfg, err := policy.LoadConfig(path)
			if err != nil {
				return err
			}
			engine := policy.New(cfg)
			d, err := hook.EvaluateCommand(args[0], engine)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			switch d.Verdict {
			case decision.Deny:
				fmt.Fprintf(w, "→ Would DENY (rule: %s, reason: %s)\n", d.PolicyID, d.Reason)
			case decision.Prompt:
				fmt.Fprintf(w, "→ Would PROMPT (rule: %s, reason: %s)\n", d.PolicyID, d.Reason)
			default:
				fmt.Fprintln(w, "→ Would ALLOW")
			}

			// See docs/cli-reference.md §8: exit 3 for anything that is not
			// a plain allow (deny OR prompt) makes this usable as a CI gate
			// over a corpus of known-safe vs. known-dangerous commands —
			// "was this flagged at all" is the useful assertion, not just
			// "was it hard-denied".
			if d.Verdict != decision.Allow {
				return &ExitCodeError{Code: 3}
			}
			return nil
		},
	}
}

func newPolicyValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate the policy file's schema without loading it into a running engine",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := resolvePolicyPath()
			if err != nil {
				return err
			}
			if _, err := policy.LoadConfig(path); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "policy file is valid")
			return nil
		},
	}
}
