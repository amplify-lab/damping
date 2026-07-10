package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/adapter/agent"
	"github.com/amplify-lab/damping/cli/i18n"
	"github.com/amplify-lab/damping/cli/policies"
	"github.com/amplify-lab/damping/core/policy"
)

// isInteractiveTTY reports whether stdin looks like a real terminal a human
// could type into — checked so a scripted/piped `damping init` (a CI
// provisioning step, an install.sh follow-up) never blocks waiting for
// language input that will never arrive. A package-level var, not a direct
// call, so tests can force either branch deterministically the same way
// cli/cmd/hook.go's newTTYPrompter var lets tests substitute a scripted
// fake instead of depending on the real environment's actual stdin.
var isInteractiveTTY = func() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

// resolveInitLanguage decides what (if anything) to write into
// policy.yaml's ui_language field this run, and returns it (empty string
// means "write nothing — leave the file's existing state, or lack of one,
// alone").
//
//   - --lang was passed explicitly: always used, on a fresh install or an
//     existing one, interactive or not — this is the scriptable override
//     path, and it must never require --force just to change a display
//     preference on an already-set-up machine.
//   - Otherwise, if a language is already configured (currentUILanguage
//     non-empty — read from whatever policy.yaml already exists before
//     this run touched it), nothing to ask: `damping init` re-run for an
//     unrelated reason (picking up new hook registrations) must not nag
//     about a question already answered.
//   - Otherwise, if stdin is a real terminal, ask once, interactively.
//   - Otherwise (non-interactive, never configured): resolve nothing.
//     i18n.ResolveLang("") still auto-detects from $LANG/$LC_ALL live at
//     every render, so a non-interactive install still gets a sensible
//     default language — it's just not pinned into the file, so it stays
//     responsive if the environment's locale ever changes.
func resolveInitLanguage(langFlag, currentUILanguage string, w io.Writer, r io.Reader) (string, error) {
	if langFlag != "" {
		switch langFlag {
		case "en", "zh-TW":
			return langFlag, nil
		default:
			return "", fmt.Errorf("init: invalid --lang %q (want \"en\" or \"zh-TW\")", langFlag)
		}
	}
	if currentUILanguage != "" {
		return "", nil
	}
	if !isInteractiveTTY() {
		return "", nil
	}
	fmt.Fprintln(w, "Language / 語言:")
	fmt.Fprintln(w, "  [1] English (default)")
	fmt.Fprintln(w, "  [2] 中文（繁體）")
	fmt.Fprint(w, "> ")
	scanner := bufio.NewScanner(r)
	if scanner.Scan() && strings.TrimSpace(scanner.Text()) == "2" {
		return string(i18n.LangZhTW), nil
	}
	// Anything else — "1", a bare Enter, unrecognized input, or the input
	// stream closing mid-prompt — defaults to English. Unlike the
	// destructive-action confirmation prompt (cli/ui), getting this wrong
	// isn't a safety question, just cosmetic, so there's no need to
	// re-prompt on invalid input the way TTYPrompter does.
	return string(i18n.LangEN), nil
}

func newInitCmd() *cobra.Command {
	var (
		agentFlag string
		force     bool
		dryRun    bool
		langFlag  string
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

			// currentUILanguage reflects the file's state *before* this run
			// writes anything — an existing, already-configured preference
			// must not be re-asked about, but a policy file this same run is
			// about to freshly create obviously has no prior answer yet
			// either way.
			var currentUILanguage string
			if cfg, cfgErr := policy.LoadConfig(policyPath); cfgErr == nil {
				currentUILanguage = cfg.UILanguage
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

			resolvedLang, err := resolveInitLanguage(langFlag, currentUILanguage, w, cmd.InOrStdin())
			if err != nil {
				return err
			}
			if resolvedLang != "" {
				if dryRun {
					fmt.Fprintf(w, "  (dry run) would set ui_language: %s in %s\n", resolvedLang, policyPath)
				} else {
					if err := policy.SetUILanguage(policyPath, resolvedLang); err != nil {
						return err
					}
					fmt.Fprintf(w, "  → Set ui_language: %s in %s\n", resolvedLang, policyPath)
				}
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
	c.Flags().StringVar(&langFlag, "lang", "", "display language for the TTY prompt and `policy test` output: en|zh-TW (default: ask interactively, or auto-detect from $LANG when non-interactive)")
	return c
}
