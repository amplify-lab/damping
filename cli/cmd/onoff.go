package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/paths"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

func newOffCmd() *cobra.Command {
	var forDuration string
	c := &cobra.Command{
		Use:   "off",
		Short: "Disable enforcement (the only sanctioned way to disable Damping — see docs/threat-model.md §4)",
		RunE: func(cmd *cobra.Command, args []string) error {
			marker, err := paths.DisabledMarker()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
				return err
			}

			var until time.Time
			if forDuration != "" {
				d, err := time.ParseDuration(forDuration)
				if err != nil {
					return fmt.Errorf("--for: %w", err)
				}
				until = time.Now().Add(d)
			}

			content := "off\n"
			if !until.IsZero() {
				content = fmt.Sprintf("off\nuntil=%s\n", until.Format(time.RFC3339))
			}
			if err := os.WriteFile(marker, []byte(content), 0o600); err != nil {
				return err
			}

			// features/self_protection.feature requires self_disable to be
			// audited like any other action — this is the single most
			// security-sensitive action in the whole tool, so it gets no
			// exemption from the audit trail. A human typing `damping off`
			// directly has no agent session, hence the "local" session id.
			if writer, hasAuditSink := newAuditWriter(); hasAuditSink {
				raw := "damping off"
				if forDuration != "" {
					raw = fmt.Sprintf("damping off --for %s", forDuration)
				}
				ev := event.New(event.NewID(), "local", "human", event.ChannelCLI, event.ActionSelfDisable, "damping off", raw,
					decision.Decision{Verdict: decision.Allow, Reason: "explicit human action at the terminal — the only sanctioned disable path"})
				if err := writer.Append(ev); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "damping: failed to write audit record for this self_disable: %v\n", err)
				}
			}

			w := cmd.OutOrStdout()
			if until.IsZero() {
				fmt.Fprintln(w, "⚠  Damping enforcement is now OFF. Your agent's commands will NOT be checked.")
				fmt.Fprintln(w, "    Run `damping on` to re-enable.")
			} else {
				fmt.Fprintf(w, "⚠  Damping enforcement paused until %s, then auto re-enables.\n", until.Format(time.Kitchen))
			}
			return nil
		},
	}
	c.Flags().StringVar(&forDuration, "for", "", "automatically re-enable after this duration (e.g. 30m)")
	return c
}

func newOnCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "on",
		Short: "Re-enable enforcement",
		RunE: func(cmd *cobra.Command, args []string) error {
			marker, err := paths.DisabledMarker()
			if err != nil {
				return err
			}
			if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintln(w, "✓ Damping enforcement is back ON.")

			// A review found this command never checked whether the
			// policy it just re-enabled can actually load — the exact
			// same underlying failure `damping status` now warns loudly
			// about (see status.go) was silently invisible right here, at
			// the one moment a user is most likely to trust "back ON"
			// means "protected" without re-checking status separately.
			if policyPath, perr := resolvePolicyPath(); perr == nil {
				if _, cerr := policy.LoadConfig(policyPath); cerr != nil {
					fmt.Fprintf(w, "⚠  But NOT protecting you — the policy file failed to load: %v\n", cerr)
				}
			}
			return nil
		},
	}
}
