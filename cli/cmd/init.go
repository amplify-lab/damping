package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/adapter/agent"
	"github.com/amplify-lab/damping/cli/policies"
)

func newInitCmd() *cobra.Command {
	var (
		agentFlag string
		force     bool
		dryRun    bool
	)
	c := &cobra.Command{
		Use:   "init",
		Short: "One-time setup: install the default policy and register agent hooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Damping %s — one-time setup\n\n", Version)

			policyPath, err := resolvePolicyPath()
			if err != nil {
				return err
			}
			if dryRun {
				fmt.Fprintf(w, "  (dry run) would write default policy to %s\n", policyPath)
			} else if _, err := os.Stat(policyPath); os.IsNotExist(err) || force {
				if err := os.MkdirAll(filepath.Dir(policyPath), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(policyPath, []byte(policies.Default), 0o600); err != nil {
					return err
				}
				fmt.Fprintf(w, "  → Installed default policy to %s\n", policyPath)
			} else {
				fmt.Fprintf(w, "  ✓ Policy already present at %s (use --force to overwrite)\n", policyPath)
			}

			for _, a := range agent.Registry {
				if agentFlag != "all" && agentFlag != a.Name {
					continue
				}
				configPath := a.ConfigPath()
				if _, err := os.Stat(filepath.Dir(configPath)); err != nil { // #nosec G703 -- configPath is a $DAMPING_*_SETTINGS/HOOKS override or a fixed default under the user's own home dir, set by the local user themselves, not attacker-influenced
					continue // agent not detected on this machine — nothing to register
				}
				fmt.Fprintf(w, "  ✓ Detected %s (%s)\n", a.DisplayName, configPath)
				if dryRun {
					fmt.Fprintf(w, "  (dry run) would register %s in %s\n", a.HookLabel, a.DisplayName)
					continue
				}
				if err := a.Install(configPath, force); err != nil {
					return err
				}
				fmt.Fprintf(w, "  → Registered %s in %s\n", a.HookLabel, a.DisplayName)
			}

			// A review found docs/cli-reference.md documented this exact
			// demo call-to-action — matching docs/architecture.md §3's
			// stated onboarding goal, "install -> first interception demo
			// in under 3 minutes" — but the code never actually printed
			// it. A real improvement worth having, not just a doc fix: the
			// single most convincing thing a new user can do right after
			// `damping init` is watch it actually catch something. Skipped
			// in --dry-run, since nothing was actually installed to try.
			if dryRun {
				fmt.Fprintln(w, "\n✓ Setup complete (dry run) — run `damping doctor` any time to re-verify this setup.")
			} else {
				fmt.Fprintln(w, "\n✓ Setup complete — try it: ask your agent to run `rm -rf /tmp/test`")
				fmt.Fprintln(w, "\nRun `damping doctor` any time to re-verify this setup.")
			}
			return nil
		},
	}
	c.Flags().StringVar(&agentFlag, "agent", "all", "which agent(s) to configure: claude-code|cursor|codex|all")
	c.Flags().BoolVar(&force, "force", false, "overwrite existing policy/hook entries")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "print what would change, write nothing")
	return c
}
