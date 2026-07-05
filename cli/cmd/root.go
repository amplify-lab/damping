// Package cmd wires the `damping` command tree — see docs/cli-reference.md
// for the full documented surface this implements against.
package cmd

import (
	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/paths"
)

// Version is set at build time via -ldflags "-X .../cmd.Version=v0.1.0".
var Version = "dev"

var configFlag string

// NewRootCmd builds the damping command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "damping",
		Short:         "One policy, one audit trail — across your terminal and your MCP servers.",
		SilenceUsage:  true,
		SilenceErrors: true, // each command prints its own user-facing messages; see main.go
		Version:       Version,
	}
	root.PersistentFlags().StringVar(&configFlag, "config", "", "path to policy.yaml (default: ~/.damping/policy.yaml, or $DAMPING_HOME/policy.yaml)")

	root.AddCommand(newInitCmd())
	root.AddCommand(newDoctorCmd())
	root.AddCommand(newStatusCmd())
	root.AddCommand(newOnCmd())
	root.AddCommand(newOffCmd())
	root.AddCommand(newLogCmd())
	root.AddCommand(newPolicyCmd())
	root.AddCommand(newHookCmd())
	return root
}

// resolvePolicyPath returns --config if set, else the default policy path.
func resolvePolicyPath() (string, error) {
	if configFlag != "" {
		return configFlag, nil
	}
	return paths.Policy()
}
