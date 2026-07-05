package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/paths"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/event"
)

// logFollowPollInterval is how often `damping log --follow` checks the
// audit file for new lines. See core/audit.Follow's doc comment for why
// this is a poll rather than a filesystem-event API. A package-level var,
// not a const, so tests can shorten it instead of waiting on the real
// interval — the same pattern cli/cmd/hook.go's newTTYPrompter var uses.
var logFollowPollInterval = 500 * time.Millisecond

func newLogCmd() *cobra.Command {
	var (
		channel string
		risk    string
		actor   string
		outcome string
		since   string
		asJSON  bool
		limit   int
		follow  bool
	)
	c := &cobra.Command{
		Use:   "log",
		Short: "Replay the local audit trail",
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := buildLogFilter(channel, risk, actor, outcome, since)
			if err != nil {
				return err
			}

			auditPath, err := paths.Audit()
			if err != nil {
				return err
			}
			// Captured before reading existing events (not after), so a
			// record appended in between lands on the "already shown" side
			// of the boundary at worst — a harmless rare duplicate — rather
			// than falling in a gap Follow would never pick up either. The
			// real os.FileInfo (not just its Size()) is passed to Follow so
			// its very first internal check has a real identity to compare
			// against — see core/audit.Follow's doc comment.
			var startInfo os.FileInfo
			if info, statErr := os.Stat(auditPath); statErr == nil {
				startInfo = info
			} else if !os.IsNotExist(statErr) {
				return statErr
			}

			events, err := audit.ReadAll(auditPath, f)
			if err != nil {
				return err
			}
			events = audit.LimitMostRecent(events, limit)
			if err := printEvents(cmd, events, asJSON); err != nil {
				return err
			}
			if !follow {
				return nil
			}

			// Stderr, not stdout — in --json mode stdout must stay pure
			// newline-delimited JSON so it's safe to pipe into jq or a
			// script; a human watching the terminal still sees this on
			// stderr, which normally shares the same terminal as stdout.
			fmt.Fprintln(cmd.ErrOrStderr(), "Watching for new events... (Ctrl+C to stop)")
			w := cmd.OutOrStdout()
			return audit.Follow(cmd.Context(), auditPath, startInfo, f, logFollowPollInterval, func(e event.ActionEvent) error {
				return printEvent(w, e, asJSON)
			})
		},
	}
	c.Flags().StringVar(&channel, "channel", "", "filter by channel (cli|mcp)")
	c.Flags().StringVar(&risk, "risk", "", "filter by risk level (low|medium|high|critical)")
	c.Flags().StringVar(&actor, "actor", "", "filter by actor")
	c.Flags().StringVar(&outcome, "outcome", "", "filter by outcome (allow|deny|prompt|degraded)")
	c.Flags().StringVar(&since, "since", "", "only show events newer than this duration ago (e.g. 24h)")
	c.Flags().BoolVar(&asJSON, "json", false, "output newline-delimited JSON instead of a table")
	c.Flags().IntVar(&limit, "limit", 0, "show at most N most-recent events (0 = no limit)")
	c.Flags().BoolVar(&follow, "follow", false, "keep watching for new events after printing existing ones (like tail -f); Ctrl+C to stop")
	c.AddCommand(newLogShowCmd())
	return c
}

func newLogShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <event_id>",
		Short: "Show the full ActionEvent for one event_id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			events, err := readFilteredEvents(audit.Filter{})
			if err != nil {
				return err
			}
			for _, e := range events {
				if e.EventID == args[0] {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					return enc.Encode(e)
				}
			}
			return fmt.Errorf("no audit event found with event_id %q", args[0])
		},
	}
}

func buildLogFilter(channel, risk, actor, outcome, since string) (audit.Filter, error) {
	f, err := audit.ParseFilter(channel, risk, actor, outcome, since)
	if err != nil {
		return audit.Filter{}, fmt.Errorf("--since: %w", err)
	}
	return f, nil
}

func readFilteredEvents(f audit.Filter) ([]event.ActionEvent, error) {
	auditPath, err := paths.Audit()
	if err != nil {
		return nil, err
	}
	return audit.ReadAll(auditPath, f)
}

func printEvents(cmd *cobra.Command, events []event.ActionEvent, asJSON bool) error {
	if len(events) == 0 {
		// In --json mode this goes to stderr, not stdout, for the same
		// reason --follow's "Watching for new events" notice does: a zero
		// non-JSON stdout line still counts as corrupting an otherwise-pure
		// NDJSON stream for a `damping log --json | jq` pipeline. Found via
		// the same BDD scenario that verified --follow --json's stdout
		// purity — it happened to start from an empty audit log and caught
		// this adjacent case too.
		w := cmd.OutOrStdout()
		if asJSON {
			w = cmd.ErrOrStderr()
		}
		fmt.Fprintln(w, "No audit events matched those filters.")
		return nil
	}

	w := cmd.OutOrStdout()
	if !asJSON {
		fmt.Fprintf(w, "%-20s %-7s %-14s %-30s %-8s %s\n", "TIME", "CHANNEL", "ACTOR", "TARGET", "RISK", "DECISION")
	}
	for _, e := range events {
		if err := printEvent(w, e, asJSON); err != nil {
			return err
		}
	}
	return nil
}

// printEvent renders a single event — the shared primitive both the
// initial batch (printEvents, one call per event, no repeated header) and
// `damping log --follow`'s live stream (one call per newly appended event)
// go through, so the two never render an event differently.
func printEvent(w io.Writer, e event.ActionEvent, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(e)
	}
	// A degraded event's Outcome() is still a plain "allow" (see
	// decision.Decision — Degraded is a separate flag, not a verdict of its
	// own), so the plain-table view otherwise renders it identically to a
	// genuine policy allow — found via a manual UX walkthrough of the real
	// binary: a doctor run clearly warns about degraded events, but nothing
	// in `damping log`'s own default output — the more natural first place
	// to look — hinted that a given row was one, only `--json`'s raw
	// "degraded":true field did. Marked here so scanning the table itself
	// is enough to notice.
	decision := string(e.Decision.Outcome())
	if e.Decision.Degraded {
		decision += " (degraded)"
	}
	_, err := fmt.Fprintf(w, "%-20s %-7s %-14s %-30s %-8s %s\n",
		e.Timestamp.Format("2006-01-02 15:04:05"),
		e.Channel, e.Actor, truncate(e.Target, 30), e.RiskLevel, decision)
	return err
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
