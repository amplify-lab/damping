package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/adapter/agent"
	"github.com/amplify-lab/damping/cli/paths"
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

			claudePath := paths.ClaudeSettings()
			cursorPath := paths.CursorHooks()

			if agentFlag == "all" || agentFlag == "claude-code" {
				if _, err := os.Stat(filepath.Dir(claudePath)); err == nil { // #nosec G703 -- claudePath is $DAMPING_CLAUDE_SETTINGS or the fixed ~/.claude/settings.json default, set by the local user themselves, not attacker-influenced
					fmt.Fprintf(w, "  ✓ Detected Claude Code (%s)\n", claudePath)
					if !dryRun {
						if err := agent.InstallClaudeCodeHook(claudePath, force); err != nil {
							return err
						}
						fmt.Fprintln(w, "  → Registered PreToolUse hook in Claude Code settings")
					} else {
						fmt.Fprintln(w, "  (dry run) would register PreToolUse hook in Claude Code settings")
					}
				}
			}
			if agentFlag == "all" || agentFlag == "cursor" {
				if _, err := os.Stat(filepath.Dir(cursorPath)); err == nil { // #nosec G703 -- cursorPath is $DAMPING_CURSOR_HOOKS or the fixed ~/.cursor/hooks.json default, set by the local user themselves, not attacker-influenced
					fmt.Fprintf(w, "  ✓ Detected Cursor (%s)\n", cursorPath)
					if !dryRun {
						if err := agent.InstallCursorHook(cursorPath, force); err != nil {
							return err
						}
						fmt.Fprintln(w, "  → Registered beforeShellExecution hook in Cursor")
					} else {
						fmt.Fprintln(w, "  (dry run) would register beforeShellExecution hook in Cursor")
					}
				}
			}

			fmt.Fprintln(w, "\n✓ Setup complete — run `damping doctor` any time to re-verify this setup.")
			return nil
		},
	}
	c.Flags().StringVar(&agentFlag, "agent", "all", "which agent(s) to configure: claude-code|cursor|all")
	c.Flags().BoolVar(&force, "force", false, "overwrite existing policy/hook entries")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "print what would change, write nothing")
	return c
}
