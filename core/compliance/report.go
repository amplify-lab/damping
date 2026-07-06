// Package compliance formats a set of event.ActionEvent records into a
// compliance-report-shaped view — the "早期差異化 demo" (M1) from
// docs/00-統一開發計畫（定案版）.md §七 item 15's development sequencing.
//
// This is deliberately NOT the full Phase 5 enterprise compliance report
// (features/compliance_report.feature) — that requires an on-prem
// deployment, AD/LDAP-bound identity, and append-only PostgreSQL history,
// none of which exist yet. This package works with whatever ActionEvents
// it's handed (the real local ~/.damping/audit.jsonl, or a synthetic demo
// set — see demo.go), so the same rendering logic will carry forward
// unchanged once Phase 5's real data source exists; only the source of
// events changes, not this package's report shape.
//
// Taiwan's FSC has not published a fixed compliance-report template (see
// docs/調查資料/phase5-enterprise-controlplane-design.md §4's regulatory
// research) — this package does not claim to produce an official
// "金管會格式" document. It produces one report structure informed by what
// FSC's existing AI guidelines and the passed AI Basic Law's accountability
// principles both emphasize (a traceable actor/identity/decision record for
// high-risk automated actions), and discloses that framing in its own
// output rather than overclaiming regulatory endorsement.
package compliance

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

// Entry is one high-risk-or-critical action surfaced in a Report's detail
// section — deliberately a flatter, report-shaped projection of ActionEvent
// rather than the full struct, so RenderMarkdown/RenderText don't need to
// know about every ActionEvent field, only the ones a compliance reviewer
// asks for (see features/compliance_report.feature's own field list: actor,
// bound identity, channel, timestamp, decision, outcome — RuleID and Reason
// are added here since a reviewer asking "why was this denied" needs them
// too).
type Entry struct {
	Timestamp time.Time
	Actor     string
	Identity  string
	Channel   event.Channel
	Target    string
	RiskLevel event.RiskLevel
	RuleID    string
	Outcome   string
	Reason    string
}

// DailyRiskCount is one day's risk-tier breakdown — Report.RiskOverTime's
// element, used by RenderHTML's timeline chart. Bucketed by calendar day
// (UTC), the natural unit for a report whose period typically spans weeks
// to a month, unlike the local dashboard's /api/stats, which buckets a much
// shorter, operator-chosen window into a fixed count of slices instead.
type DailyRiskCount struct {
	Date                        time.Time
	Low, Medium, High, Critical int
}

// RuleBreakdown is one row of Report.TopRules — how many times one rule id
// matched across the reporting period.
type RuleBreakdown struct {
	RuleID string
	Count  int
}

// reportTopRulesLimit caps Report.TopRules the same way the local
// dashboard's own top-rules panel caps itself (cli/dashboard/stats.go's
// topRulesLimit) — a glanceable "what's actually firing" summary, not an
// exhaustive per-rule report.
const reportTopRulesLimit = 10

// Report is the generated compliance view over a slice of ActionEvents.
type Report struct {
	GeneratedAt     time.Time
	PeriodStart     time.Time
	PeriodEnd       time.Time
	IsDemo          bool
	TotalActions    int
	RiskCounts      map[event.RiskLevel]int
	OutcomeCounts   map[string]int
	HighRiskEntries []Entry

	// RiskOverTime, TopRules, DeniedCount, and CriticalDeniedCount are
	// derived summary numbers RenderHTML's charts are built from —
	// RenderMarkdown/RenderText don't need them (their own summary section
	// reads RiskCounts/OutcomeCounts directly), but they're computed here in
	// Generate rather than re-derived from raw events at render time, so
	// every Render* method stays a pure function of the same Report value.
	RiskOverTime        []DailyRiskCount
	TopRules            []RuleBreakdown
	DeniedCount         int
	CriticalDeniedCount int
}

// highRiskTiers are the only risk levels that belong in a Report's detail
// section — a report listing every low-risk allow alongside genuine
// high-risk interceptions would bury the signal a reviewer actually needs,
// per features/compliance_report_demo.feature's explicit
// "should not clutter" scenario. Low-risk actions still count toward
// RiskCounts/OutcomeCounts, just not the entry list.
var highRiskTiers = map[event.RiskLevel]bool{
	event.RiskCritical: true,
	event.RiskHigh:     true,
}

// Generate builds a Report from events. isDemo marks whether events came
// from the synthetic demo dataset (demo.go) rather than a real audit log —
// this flag alone drives every "this is/isn't a demo" disclosure in the
// rendered output, so a real report generated from actual customer history
// can never accidentally claim to be a demo, and vice versa (see
// TestReport_RenderMarkdown_NonDemoDoesNotClaimToBeDemo).
func Generate(events []event.ActionEvent, isDemo bool) Report {
	r := Report{
		GeneratedAt:   time.Now(),
		IsDemo:        isDemo,
		TotalActions:  len(events),
		RiskCounts:    map[event.RiskLevel]int{},
		OutcomeCounts: map[string]int{},
	}
	ruleCounts := map[string]int{}
	dailyBuckets := map[time.Time]*DailyRiskCount{}
	var dailyOrder []time.Time

	for i, e := range events {
		r.RiskCounts[e.RiskLevel]++
		outcome := string(e.Decision.Outcome())
		r.OutcomeCounts[outcome]++

		if i == 0 || e.Timestamp.Before(r.PeriodStart) {
			r.PeriodStart = e.Timestamp
		}
		if i == 0 || e.Timestamp.After(r.PeriodEnd) {
			r.PeriodEnd = e.Timestamp
		}

		day := e.Timestamp.UTC().Truncate(24 * time.Hour)
		bucket, ok := dailyBuckets[day]
		if !ok {
			bucket = &DailyRiskCount{Date: day}
			dailyBuckets[day] = bucket
			dailyOrder = append(dailyOrder, day)
		}
		switch e.RiskLevel {
		case event.RiskLow:
			bucket.Low++
		case event.RiskMedium:
			bucket.Medium++
		case event.RiskHigh:
			bucket.High++
		case event.RiskCritical:
			bucket.Critical++
		}

		if e.Decision.PolicyID != "" {
			ruleCounts[e.Decision.PolicyID]++
		}
		if decision.Verdict(outcome) == decision.Deny {
			r.DeniedCount++
			if e.RiskLevel == event.RiskCritical {
				r.CriticalDeniedCount++
			}
		}

		if !highRiskTiers[e.RiskLevel] {
			continue
		}
		r.HighRiskEntries = append(r.HighRiskEntries, Entry{
			Timestamp: e.Timestamp,
			Actor:     e.Actor,
			Identity:  e.Identity,
			Channel:   e.Channel,
			Target:    e.Target,
			RiskLevel: e.RiskLevel,
			RuleID:    e.Decision.PolicyID,
			Outcome:   outcome,
			Reason:    e.Decision.Reason,
		})
	}

	sort.Slice(dailyOrder, func(i, j int) bool { return dailyOrder[i].Before(dailyOrder[j]) })
	for _, d := range dailyOrder {
		r.RiskOverTime = append(r.RiskOverTime, *dailyBuckets[d])
	}

	for id, count := range ruleCounts {
		r.TopRules = append(r.TopRules, RuleBreakdown{RuleID: id, Count: count})
	}
	sort.Slice(r.TopRules, func(i, j int) bool {
		if r.TopRules[i].Count != r.TopRules[j].Count {
			return r.TopRules[i].Count > r.TopRules[j].Count
		}
		return r.TopRules[i].RuleID < r.TopRules[j].RuleID
	})
	if len(r.TopRules) > reportTopRulesLimit {
		r.TopRules = r.TopRules[:reportTopRulesLimit]
	}

	return r
}

// RenderMarkdown produces the polished, shareable form of a Report — the
// format meant to actually be shown to (or handed to) a prospective
// customer or their compliance officer, per M1's own purpose.
func (r Report) RenderMarkdown() string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Damping Compliance Report\n\n")
	if r.IsDemo {
		fmt.Fprintf(&b, "> **This is a demo report built on a synthetic 30-day dataset, not a real customer's audit history.** It exists to show the shape of a real report before any real deployment.\n\n")
	}
	fmt.Fprintf(&b, "> **Scope disclosure:** this is not an official regulator-issued report template — Taiwan's FSC has not published a fixed compliance-report format as of this report's generation. It is structured around what FSC's existing AI guidelines and the passed AI Basic Law's accountability principles both emphasize: a traceable actor/identity/decision record for every high-risk automated action. It is also not the same as the full Phase 5 enterprise compliance report (on-prem deployment, AD/LDAP-bound identity, append-only PostgreSQL history) — this is a lighter-weight report over whatever audit history is available today.\n\n")

	fmt.Fprintf(&b, "**Generated:** %s\n\n", r.GeneratedAt.Format(time.RFC3339))
	if !r.PeriodStart.IsZero() {
		fmt.Fprintf(&b, "**Period covered:** %s to %s\n\n", r.PeriodStart.Format("2006-01-02"), r.PeriodEnd.Format("2006-01-02"))
	}

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "- Total actions evaluated: %d\n", r.TotalActions)
	for _, tier := range []event.RiskLevel{event.RiskCritical, event.RiskHigh, event.RiskMedium, event.RiskLow} {
		if n := r.RiskCounts[tier]; n > 0 {
			fmt.Fprintf(&b, "- Risk %s: %d\n", tier, n)
		}
	}
	for outcome, n := range r.OutcomeCounts {
		fmt.Fprintf(&b, "- Outcome %s: %d\n", outcome, n)
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "## High-Risk and Critical Actions\n\n")
	if len(r.HighRiskEntries) == 0 {
		fmt.Fprintf(&b, "No high-risk or critical actions occurred in this period.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "| Timestamp | Actor | Identity | Channel | Target | Risk | Rule | Outcome |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|---|\n")
	for _, e := range r.HighRiskEntries {
		identity := e.Identity
		if identity == "" {
			identity = "(unbound)"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			e.Timestamp.Format("2006-01-02 15:04"), e.Actor, identity, e.Channel,
			truncateForReport(e.Target, 40), e.RiskLevel, e.RuleID, e.Outcome)
	}
	return b.String()
}

// RenderText is the plain-terminal form — same content as RenderMarkdown
// without table/markdown syntax, for a quick `damping compliance-report
// demo --format text` look without piping to a renderer.
func (r Report) RenderText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Damping Compliance Report%s\n", ifDemo(r.IsDemo, " (DEMO — synthetic data)"))
	fmt.Fprintf(&b, "Generated: %s\n", r.GeneratedAt.Format(time.RFC3339))
	if !r.PeriodStart.IsZero() {
		fmt.Fprintf(&b, "Period: %s to %s\n", r.PeriodStart.Format("2006-01-02"), r.PeriodEnd.Format("2006-01-02"))
	}
	fmt.Fprintf(&b, "Total actions: %d\n\n", r.TotalActions)

	if len(r.HighRiskEntries) == 0 {
		fmt.Fprintf(&b, "No high-risk or critical actions occurred in this period.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "%-20s %-10s %-20s %-7s %-30s %-8s %-35s %s\n",
		"TIME", "ACTOR", "IDENTITY", "CHANNEL", "TARGET", "RISK", "RULE", "OUTCOME")
	for _, e := range r.HighRiskEntries {
		identity := e.Identity
		if identity == "" {
			identity = "(unbound)"
		}
		fmt.Fprintf(&b, "%-20s %-10s %-20s %-7s %-30s %-8s %-35s %s\n",
			e.Timestamp.Format("2006-01-02 15:04"), e.Actor, identity, e.Channel,
			truncateForReport(e.Target, 30), e.RiskLevel, e.RuleID, e.Outcome)
	}
	return b.String()
}

// RenderJSON is the structured form, for future integration/parsing —
// deliberately the same Report struct godoc.Generate returns, not a
// separately-hand-maintained shape.
func (r Report) RenderJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func ifDemo(demo bool, s string) string {
	if demo {
		return s
	}
	return ""
}

func truncateForReport(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
