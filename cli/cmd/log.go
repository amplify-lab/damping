package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/paths"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/event"
)

func newLogCmd() *cobra.Command {
	var (
		channel string
		risk    string
		actor   string
		outcome string
		since   string
		asJSON  bool
	)
	c := &cobra.Command{
		Use:   "log",
		Short: "Replay the local audit trail",
		RunE: func(cmd *cobra.Command, args []string) error {
			auditPath, err := paths.Audit()
			if err != nil {
				return err
			}

			f := audit.Filter{
				Channel: event.Channel(channel),
				Risk:    event.RiskLevel(risk),
				Actor:   actor,
				Outcome: outcome,
			}
			if since != "" {
				d, err := time.ParseDuration(since)
				if err != nil {
					return fmt.Errorf("--since: %w", err)
				}
				f.Since = time.Now().Add(-d)
			}

			events, err := audit.ReadAll(auditPath, f)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if len(events) == 0 {
				fmt.Fprintln(w, "No audit events matched those filters.")
				return nil
			}

			if asJSON {
				enc := json.NewEncoder(w)
				for _, e := range events {
					if err := enc.Encode(e); err != nil {
						return err
					}
				}
				return nil
			}

			fmt.Fprintf(w, "%-20s %-7s %-14s %-30s %-8s %s\n", "TIME", "CHANNEL", "ACTOR", "TARGET", "RISK", "DECISION")
			for _, e := range events {
				fmt.Fprintf(w, "%-20s %-7s %-14s %-30s %-8s %s\n",
					e.Timestamp.Format("2006-01-02 15:04:05"),
					e.Channel, e.Actor, truncate(e.Target, 30), e.RiskLevel, e.Decision.Outcome())
			}
			return nil
		},
	}
	c.Flags().StringVar(&channel, "channel", "", "filter by channel (cli|mcp)")
	c.Flags().StringVar(&risk, "risk", "", "filter by risk level (low|medium|high|critical)")
	c.Flags().StringVar(&actor, "actor", "", "filter by actor")
	c.Flags().StringVar(&outcome, "outcome", "", "filter by outcome (allow|deny|prompt|degraded)")
	c.Flags().StringVar(&since, "since", "", "only show events newer than this duration ago (e.g. 24h)")
	c.Flags().BoolVar(&asJSON, "json", false, "output newline-delimited JSON instead of a table")
	return c
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
