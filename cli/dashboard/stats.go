package dashboard

import (
	"net/http"
	"sort"
	"time"

	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

// riskOverTimeBuckets is a fixed bucket count for /api/stats's time series,
// regardless of the filtered period's actual span — the chart just needs
// enough points to draw a meaningful line, and a fixed count keeps the
// bucketing arithmetic simple (no day-vs-hour granularity switch to get
// wrong at the boundary) at the cost of each bucket's width varying with
// the period length. 24 was picked as "enough resolution to see a shape,
// not so many the bars go illegibly thin on a typical dashboard width."
const riskOverTimeBuckets = 24

// topRulesLimit caps /api/stats's rule-triggered-most breakdown — a
// glanceable "what's actually firing" panel (docs/ux-dashboard-spec.md
// §2.2's per-rule pattern, scoped down to this local install), not an
// exhaustive report; `damping log --policy-id <id>` is where the full
// detail for one rule belongs.
const topRulesLimit = 10

// outcomeCounts mirrors cli/cmd/log.go's printEvent convention: Degraded is
// an orthogonal flag on a Decision, not a third outcome value alongside
// Allow/Deny — a degraded event's Outcome() is still "allow" (see
// core/decision.Decision), so it's counted here in both places rather than
// exclusively in one.
type outcomeCounts struct {
	Allow    int `json:"allow"`
	Deny     int `json:"deny"`
	Degraded int `json:"degraded"`
}

// riskBucket is one point of /api/stats's risk-over-time series: how many
// events at each risk tier fell inside this time slice.
type riskBucket struct {
	BucketStart time.Time `json:"bucket_start"`
	Low         int       `json:"low"`
	Medium      int       `json:"medium"`
	High        int       `json:"high"`
	Critical    int       `json:"critical"`
}

// ruleCount is one row of /api/stats's top-rules breakdown.
type ruleCount struct {
	PolicyID string `json:"policy_id"`
	Risk     string `json:"risk"`
	Count    int    `json:"count"`
}

// stats is /api/stats's response shape — computed over the full filtered
// audit history (audit.ReadAll, no defaultEventsLimit truncation), unlike
// /api/events, whose own default limit exists specifically so the live
// table stays fast. A summary count is only trustworthy if it's never
// silently short of the real total.
type stats struct {
	PeriodStart   time.Time     `json:"period_start,omitempty"`
	PeriodEnd     time.Time     `json:"period_end"`
	TotalEvents   int           `json:"total_events"`
	OutcomeCounts outcomeCounts `json:"outcome_counts"`
	RiskOverTime  []riskBucket  `json:"risk_over_time"`
	TopRules      []ruleCount   `json:"top_rules"`
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilterQuery(r)
	if err != nil {
		http.Error(w, "invalid filter: "+err.Error(), http.StatusBadRequest)
		return
	}
	all, err := s.auditEvents()
	if err != nil {
		http.Error(w, "reading audit log: "+err.Error(), http.StatusInternalServerError)
		return
	}
	events := filterEvents(all, f)
	writeJSON(w, computeStats(events, f))
}

// computeStats is the pure function behind handleStats, split out so tests
// can exercise the aggregation logic directly without an HTTP round trip.
// events is assumed already filtered (by ReadAll(path, f)) and in
// chronological order, matching ReadAll's own contract.
func computeStats(events []event.ActionEvent, f audit.Filter) stats {
	out := stats{
		PeriodEnd:    time.Now(),
		TopRules:     []ruleCount{},
		RiskOverTime: []riskBucket{},
	}
	if !f.Since.IsZero() {
		out.PeriodStart = f.Since
	}
	if !f.Until.IsZero() {
		out.PeriodEnd = f.Until
	}
	out.TotalEvents = len(events)

	ruleCounts := make(map[string]*ruleCount)
	for _, e := range events {
		switch e.Decision.Outcome() {
		case decision.Allow:
			out.OutcomeCounts.Allow++
		case decision.Deny:
			out.OutcomeCounts.Deny++
		}
		if e.Decision.Degraded {
			out.OutcomeCounts.Degraded++
		}
		if e.Decision.PolicyID == "" {
			continue // a plain allow with no matched rule — nothing to attribute to a rule breakdown
		}
		rc, ok := ruleCounts[e.Decision.PolicyID]
		if !ok {
			rc = &ruleCount{PolicyID: e.Decision.PolicyID, Risk: e.Decision.Risk}
			ruleCounts[e.Decision.PolicyID] = rc
		}
		rc.Count++
	}

	for _, rc := range ruleCounts {
		out.TopRules = append(out.TopRules, *rc)
	}
	sort.Slice(out.TopRules, func(i, j int) bool {
		if out.TopRules[i].Count != out.TopRules[j].Count {
			return out.TopRules[i].Count > out.TopRules[j].Count
		}
		return out.TopRules[i].PolicyID < out.TopRules[j].PolicyID // stable tie-break, not map iteration order
	})
	if len(out.TopRules) > topRulesLimit {
		out.TopRules = out.TopRules[:topRulesLimit]
	}

	out.RiskOverTime = bucketRiskOverTime(events, f)
	return out
}

// bucketRiskOverTime divides events into riskOverTimeBuckets equal-width
// time slices spanning [start, end] and counts each event's risk tier into
// whichever bucket its timestamp falls in. start/end come from the filter's
// own Since/Until when set (so the chart's x-axis matches exactly what the
// user asked to see, including empty buckets at either end), falling back to
// the earliest/latest event timestamp otherwise.
func bucketRiskOverTime(events []event.ActionEvent, f audit.Filter) []riskBucket {
	if len(events) == 0 {
		return []riskBucket{}
	}
	start, end := f.Since, f.Until
	if start.IsZero() {
		start = events[0].Timestamp
	}
	if end.IsZero() {
		end = events[len(events)-1].Timestamp
	}
	if !end.After(start) {
		end = start.Add(time.Second) // degenerate single-instant range: give bucketing something to divide
	}

	buckets := make([]riskBucket, riskOverTimeBuckets)
	width := end.Sub(start) / riskOverTimeBuckets
	for i := range buckets {
		buckets[i].BucketStart = start.Add(time.Duration(i) * width)
	}

	for _, e := range events {
		idx := 0
		if width > 0 {
			idx = int(e.Timestamp.Sub(start) / width)
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= riskOverTimeBuckets {
			idx = riskOverTimeBuckets - 1
		}
		switch e.RiskLevel {
		case event.RiskLow:
			buckets[idx].Low++
		case event.RiskMedium:
			buckets[idx].Medium++
		case event.RiskHigh:
			buckets[idx].High++
		case event.RiskCritical:
			buckets[idx].Critical++
		}
	}
	return buckets
}
