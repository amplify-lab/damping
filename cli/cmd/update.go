package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/update"
)

func newUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update damping to the latest release",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()

			// ForceCheck, not Check: DAMPING_NO_UPDATE_CHECK only silences
			// the passive background notice other commands print — a human
			// who explicitly typed `damping update` asked a real question
			// and must get a real answer regardless of that env var. See
			// update.ForceCheck's doc comment for the exact split.
			info := update.ForceCheck(cmd.Context(), Version)
			if !info.Available {
				fmt.Fprintf(w, "damping is already up to date (%s).\n", Version)
				return nil
			}

			method := update.CurrentMethod()

			if method.NeedsElevation {
				// Informational, not an error: damping never re-execs itself
				// with elevated privileges on the user's behalf (that would
				// mean silently prompting for sudo/UAC from inside a CLI a
				// human didn't explicitly invoke that way), so the honest
				// move is to hand back the exact command and let the human
				// decide whether to run it themselves.
				fmt.Fprintf(w, "damping %s -> %s is available, but the install location needs elevated privileges damping won't request on your behalf.\n", info.Current, info.Latest)
				fmt.Fprintf(w, "Run this yourself: %s\n", method.Display())
				return nil
			}

			fmt.Fprintf(w, "Updating %s -> %s via: %s\n", info.Current, info.Latest, method.Display())
			if err := update.Apply(cmd.Context(), method, w); err != nil {
				return err
			}
			fmt.Fprintf(w, "✓ Updated to %s.\n", info.Latest)
			return nil
		},
	}
}
