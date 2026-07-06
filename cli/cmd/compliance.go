package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/compliance"
)

// newComplianceReportCmd is the M1 "early differentiator demo" from
// docs/00-統一開發計畫（定案版）.md §七 item 15's development sequencing —
// see core/compliance's package doc comment for the full scope disclosure
// (not the Phase 5 enterprise feature, not an official regulator template).
func newComplianceReportCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "compliance-report",
		Short: "Generate a compliance-report-shaped view of the audit trail (early demo, not the full Phase 5 enterprise feature)",
	}
	c.AddCommand(newComplianceReportDemoCmd())
	c.AddCommand(newComplianceReportExportCmd())
	return c
}

func newComplianceReportDemoCmd() *cobra.Command {
	var format string
	c := &cobra.Command{
		Use:   "demo",
		Short: "Generate a demo compliance report from a synthetic 30-day dataset — no real audit history required",
		RunE: func(cmd *cobra.Command, args []string) error {
			r := compliance.Generate(compliance.SyntheticDemoDataset(), true)
			return renderComplianceReport(cmd, r, format)
		},
	}
	c.Flags().StringVar(&format, "format", "markdown", "output format (markdown|text|json)")
	return c
}

func newComplianceReportExportCmd() *cobra.Command {
	var (
		format string
		since  string
	)
	c := &cobra.Command{
		Use:   "export",
		Short: "Generate a compliance report from the real local audit trail",
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := audit.ParseFilter("", "", "", "", since)
			if err != nil {
				return fmt.Errorf("--since: %w", err)
			}
			events, err := readFilteredEvents(f)
			if err != nil {
				return err
			}
			r := compliance.Generate(events, false)
			return renderComplianceReport(cmd, r, format)
		},
	}
	c.Flags().StringVar(&format, "format", "markdown", "output format (markdown|text|json)")
	c.Flags().StringVar(&since, "since", "", "only include events newer than this duration ago (e.g. 720h for 30 days); empty means the entire local audit log")
	return c
}

func renderComplianceReport(cmd *cobra.Command, r compliance.Report, format string) error {
	w := cmd.OutOrStdout()
	switch format {
	case "markdown", "":
		_, err := fmt.Fprint(w, r.RenderMarkdown())
		return err
	case "text":
		_, err := fmt.Fprint(w, r.RenderText())
		return err
	case "json":
		data, err := r.RenderJSON()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(data))
		return err
	default:
		return fmt.Errorf("unknown --format %q (want markdown|text|json)", format)
	}
}
