package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/paths"
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
			fmt.Fprintln(cmd.OutOrStdout(), "✓ Damping enforcement is back ON.")
			return nil
		},
	}
}

// IsDisabled reports whether enforcement is currently off, respecting an
// expired --for duration (auto re-enable) by treating it as already on.
// Shared by `damping status`, `damping doctor`, and the hook entrypoint.
func IsDisabled() (bool, error) {
	marker, err := paths.DisabledMarker()
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(marker)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	var until time.Time
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "until="); ok {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				until = t
			}
		}
	}
	if !until.IsZero() && time.Now().After(until) {
		_ = os.Remove(marker)
		return false, nil
	}
	return true, nil
}
