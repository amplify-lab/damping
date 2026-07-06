package compliance

import (
	"bytes"
	"html/template"
	"time"
)

// riskTierColors mirrors cli/dashboard/static/charts.js's RISK_COLORS
// palette — the same four colors mean the same four risk tiers everywhere
// in the product, whether that's the live local dashboard or a report
// handed to a customer's compliance officer.
var riskTierColors = []struct {
	get   func(DailyRiskCount) int
	color string
}{
	{func(d DailyRiskCount) int { return d.Low }, "#14b8a6"},
	{func(d DailyRiskCount) int { return d.Medium }, "#eab308"},
	{func(d DailyRiskCount) int { return d.High }, "#f59e0b"},
	{func(d DailyRiskCount) int { return d.Critical }, "#ef4444"},
}

// htmlChartWidth/htmlChartHeight are the risk-over-time SVG's viewBox
// dimensions — arbitrary but fixed units, scaled to fill its container via
// the template's width:100% CSS, the same viewBox-as-coordinate-space
// technique cli/dashboard/static/charts.js's stackedRiskOverTime uses.
const (
	htmlChartWidth  = 600.0
	htmlChartHeight = 160.0
)

// htmlBar is one pre-computed SVG <rect> — geometry is computed here in Go,
// not inside the template, so the template itself only ever interpolates
// plain numbers and pre-escaped-by-html/template text, never performs
// arithmetic or conditional layout logic of its own.
type htmlBar struct {
	X, Y, Width, Height float64
	Color               string
}

// htmlBarGroup is one day's stacked bar in the risk-over-time chart.
type htmlBarGroup struct {
	Bars  []htmlBar
	Label string
}

// htmlRuleRow is one row of the top-triggered-rules bar list.
type htmlRuleRow struct {
	RuleID       string
	Count        int
	WidthPercent float64
}

// htmlView is RenderHTML's template data: the Report's own fields plus the
// pre-computed chart geometry derived from Report.RiskOverTime/TopRules.
type htmlView struct {
	Report
	ChartWidth, ChartHeight float64
	RiskChartGroups         []htmlBarGroup
	RuleRows                []htmlRuleRow
}

// RenderHTML produces a single, self-contained HTML file — inline CSS, no
// external stylesheet/script/font references — meant to be handed directly
// to a prospective customer or their compliance officer, printed, or
// archived, the same way `compliance-report ... --format markdown` already
// is, but with the risk-over-time and top-triggered-rules charts rendered
// as inline SVG rather than left to a markdown renderer that may not
// support them.
//
// Unlike RenderMarkdown/RenderText, which build their output with raw
// fmt.Fprintf string interpolation (safe for those plain-text formats), this
// method goes through html/template specifically for its context-aware
// auto-escaping: Entry.Target and Entry.Reason both flow from a real
// ActionEvent an adversarial agent session could have influenced (see
// docs/threat-model.md §3), and reusing the markdown/text formatters' raw
// interpolation pattern here would let one of those fields break out of its
// HTML context. Every field reaches the template through {{.}} — never
// through template.HTML/template.JS, which would suppress escaping — so
// this holds regardless of which specific field carries adversarial text.
func (r Report) RenderHTML() (string, error) {
	v := htmlView{
		Report:          r,
		ChartWidth:      htmlChartWidth,
		ChartHeight:     htmlChartHeight,
		RiskChartGroups: buildRiskChartGroups(r.RiskOverTime),
		RuleRows:        buildRuleRows(r.TopRules),
	}
	var buf bytes.Buffer
	if err := reportHTMLTemplate.Execute(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func buildRiskChartGroups(buckets []DailyRiskCount) []htmlBarGroup {
	if len(buckets) == 0 {
		return nil
	}
	maxTotal := 1
	for _, b := range buckets {
		if total := b.Low + b.Medium + b.High + b.Critical; total > maxTotal {
			maxTotal = total
		}
	}
	barW := htmlChartWidth / float64(len(buckets))
	groups := make([]htmlBarGroup, len(buckets))
	for i, b := range buckets {
		yCursor := htmlChartHeight
		var bars []htmlBar
		for _, tier := range riskTierColors {
			count := tier.get(b)
			if count == 0 {
				continue
			}
			barH := float64(count) / float64(maxTotal) * htmlChartHeight
			bars = append(bars, htmlBar{
				X: float64(i)*barW + 1, Y: yCursor - barH,
				Width: barW - 2, Height: barH, Color: tier.color,
			})
			yCursor -= barH
		}
		groups[i] = htmlBarGroup{Bars: bars, Label: b.Date.Format("01/02")}
	}
	return groups
}

func buildRuleRows(rules []RuleBreakdown) []htmlRuleRow {
	if len(rules) == 0 {
		return nil
	}
	maxCount := 1
	for _, rl := range rules {
		if rl.Count > maxCount {
			maxCount = rl.Count
		}
	}
	rows := make([]htmlRuleRow, len(rules))
	for i, rl := range rules {
		rows[i] = htmlRuleRow{RuleID: rl.RuleID, Count: rl.Count, WidthPercent: float64(rl.Count) / float64(maxCount) * 100}
	}
	return rows
}

// unboundIdentity fills in the same "(unbound)" placeholder
// RenderMarkdown/RenderText use for an Entry with no bound identity — a
// template func rather than a pre-processing pass over HighRiskEntries, so
// RenderHTML stays a pure function of the Report value it's called on.
func unboundIdentity(identity string) string {
	if identity == "" {
		return "(unbound)"
	}
	return identity
}

var reportHTMLTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"unboundIdentity": unboundIdentity,
	"dateFmt":         func(t time.Time) string { return t.Format("2006-01-02") },
	"dateTimeFmt":     func(t time.Time) string { return t.Format("2006-01-02 15:04") },
}).Parse(reportHTMLSource))

const reportHTMLSource = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Damping Compliance Report</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 2rem; background: #f8fafc; color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
  .doc { max-width: 900px; margin: 0 auto; }
  header.banner { display: flex; align-items: center; gap: 0.75rem; border-bottom: 2px solid #0f172a; padding-bottom: 1rem; margin-bottom: 1.5rem; }
  header.banner h1 { font-size: 1.5rem; margin: 0; }
  .brand-mark { color: #0d9488; font-weight: 700; font-family: ui-monospace, monospace; }
  .callout { border-left: 4px solid #0d9488; background: #f0fdfa; padding: 0.75rem 1rem; margin-bottom: 0.75rem; font-size: 0.9rem; }
  .callout.demo { border-color: #f59e0b; background: #fffbeb; }
  .meta { font-size: 0.85rem; color: #475569; margin-bottom: 1.5rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; }
  .summary-card { border: 1px solid #e2e8f0; border-radius: 6px; padding: 0.75rem; background: #fff; }
  .summary-card .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.03em; color: #64748b; }
  .summary-card .value { font-size: 1.4rem; font-weight: 600; margin-top: 0.25rem; font-family: ui-monospace, monospace; }
  section { margin-bottom: 2rem; }
  h2 { font-size: 1.05rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.4rem; }
  .chart-card { border: 1px solid #e2e8f0; border-radius: 6px; padding: 1rem; background: #fff; }
  svg.chart { width: 100%; height: auto; display: block; }
  .legend { font-size: 0.8rem; color: #475569; margin-top: 0.5rem; }
  .legend span { margin-right: 1rem; }
  .legend i { display: inline-block; width: 0.6rem; height: 0.6rem; border-radius: 50%; margin-right: 0.3rem; vertical-align: middle; }
  .rule-row { display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; margin-bottom: 0.4rem; }
  .rule-label { font-family: ui-monospace, monospace; width: 260px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .rule-track { flex: 1; height: 0.9rem; background: #f1f5f9; border-radius: 4px; overflow: hidden; }
  .rule-fill { height: 100%; background: #0d9488; }
  .rule-count { width: 2rem; text-align: right; color: #475569; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.5rem 0.6rem; border-bottom: 1px solid #e2e8f0; }
  th { color: #475569; font-weight: 600; }
  tr:nth-child(even) td { background: #f8fafc; }
  .risk-badge, .outcome-badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 4px; font-size: 0.78rem; font-weight: 600; }
  .risk-low { background: #ccfbf1; color: #0f766e; }
  .risk-medium { background: #fef9c3; color: #854d0e; }
  .risk-high { background: #fef3c7; color: #92400e; }
  .risk-critical { background: #fee2e2; color: #991b1b; }
  .outcome-allow { background: #ccfbf1; color: #0f766e; }
  .outcome-deny { background: #fee2e2; color: #991b1b; }
  footer { font-size: 0.75rem; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 0.75rem; }
</style>
</head>
<body>
<div class="doc">
  <header class="banner">
    <span class="brand-mark">damping</span>
    <h1>Compliance Report</h1>
  </header>

  {{if .IsDemo}}
  <div class="callout demo"><strong>This is a demo report built on a synthetic 30-day dataset, not a real customer's audit history.</strong> It exists to show the shape of a real report before any real deployment.</div>
  {{end}}
  <div class="callout">
    <strong>Scope disclosure:</strong> this is not an official regulator-issued report template — Taiwan's FSC has not published a fixed compliance-report format as of this report's generation. It is structured around what FSC's existing AI guidelines and the passed AI Basic Law's accountability principles both emphasize: a traceable actor/identity/decision record for every high-risk automated action. It is also not the same as the full Phase 5 enterprise compliance report (on-prem deployment, AD/LDAP-bound identity, append-only PostgreSQL history) — this is a lighter-weight report over whatever audit history is available today.
  </div>

  <div class="meta">
    Generated {{.GeneratedAt.Format "2006-01-02 15:04 MST"}}{{if not .PeriodStart.IsZero}} &middot; period {{dateFmt .PeriodStart}} to {{dateFmt .PeriodEnd}}{{end}}
  </div>

  <section class="summary-grid">
    <div class="summary-card"><div class="label">Total actions</div><div class="value">{{.TotalActions}}</div></div>
    <div class="summary-card"><div class="label">Denied</div><div class="value">{{.DeniedCount}}</div></div>
    <div class="summary-card"><div class="label">Critical &amp; denied</div><div class="value">{{.CriticalDeniedCount}}</div></div>
    <div class="summary-card"><div class="label">High-risk entries</div><div class="value">{{len .HighRiskEntries}}</div></div>
  </section>

  {{if .RiskChartGroups}}
  <section>
    <h2>Risk over time</h2>
    <div class="chart-card">
      <svg class="chart" viewBox="0 0 {{.ChartWidth}} {{.ChartHeight}}" preserveAspectRatio="none">
        {{range .RiskChartGroups}}{{range .Bars}}<rect x="{{.X}}" y="{{.Y}}" width="{{.Width}}" height="{{.Height}}" fill="{{.Color}}"><title>{{.Color}}</title></rect>{{end}}{{end}}
      </svg>
      <div class="legend">
        <span><i style="background:#14b8a6"></i>low</span>
        <span><i style="background:#eab308"></i>medium</span>
        <span><i style="background:#f59e0b"></i>high</span>
        <span><i style="background:#ef4444"></i>critical</span>
      </div>
    </div>
  </section>
  {{end}}

  {{if .RuleRows}}
  <section>
    <h2>Top triggered rules</h2>
    <div class="chart-card">
      {{range .RuleRows}}
      <div class="rule-row">
        <span class="rule-label" title="{{.RuleID}}">{{.RuleID}}</span>
        <div class="rule-track"><div class="rule-fill" style="width:{{.WidthPercent}}%"></div></div>
        <span class="rule-count">{{.Count}}</span>
      </div>
      {{end}}
    </div>
  </section>
  {{end}}

  <section>
    <h2>High-Risk and Critical Actions</h2>
    {{if .HighRiskEntries}}
    <table>
      <thead><tr><th>Timestamp</th><th>Actor</th><th>Identity</th><th>Channel</th><th>Target</th><th>Risk</th><th>Rule</th><th>Outcome</th></tr></thead>
      <tbody>
        {{range .HighRiskEntries}}
        <tr>
          <td>{{dateTimeFmt .Timestamp}}</td>
          <td>{{.Actor}}</td>
          <td>{{unboundIdentity .Identity}}</td>
          <td>{{.Channel}}</td>
          <td>{{.Target}}</td>
          <td><span class="risk-badge risk-{{.RiskLevel}}">{{.RiskLevel}}</span></td>
          <td>{{.RuleID}}</td>
          <td><span class="outcome-badge outcome-{{.Outcome}}">{{.Outcome}}</span></td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
    <p>No high-risk or critical actions occurred in this period.</p>
    {{end}}
  </section>

  <footer>Generated by damping compliance-report — see docs/cli-reference.md §7.1. Not an official regulator-issued document.</footer>
</div>
</body>
</html>
`
