package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

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
				return nil
			}
			fmt.Fprintf(w, "Policy:  %s (%d rules)\n", path, len(cfg.Rules))
			return nil
		},
	}
}
