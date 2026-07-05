package dashboard

import (
	"net/http"
	"sort"

	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/event"
)

// maxSessions and maxPointsPerSession bound the /api/sessions response —
// this is a glanceable "recent activity" panel (docs/ux-dashboard-spec.md
// §2.2's per-member risk-sparklines, adapted here to per-session since a
// local single-user install has no team roster), not an exhaustive report;
// `damping log --session <id>` (via --actor/--since filters) is where a
// full history belongs.
const (
	maxSessions         = 8
	maxPointsPerSession = 30
)

// sessionSpark is one row of /api/sessions: a session's risk level over
// time, encoded as plain integers (never raw event fields like Target/Raw,
// which can contain an adversarially-crafted agent command) so the
// dashboard's client-side sparkline renderer never has to treat this
// payload as anything other than trusted numbers — see index.html's
// renderSparkline, which builds the SVG via DOM APIs, not string/HTML
// interpolation, specifically so no event-derived text ever needs escaping
// twice.
type sessionSpark struct {
	SessionID string `json:"session_id"`
	Actor     string `json:"actor"`
	Points    []int  `json:"points"`  // risk level per event in chronological order: low=1 .. critical=4
	Settled   bool   `json:"settled"` // true if the most recent point is the lowest risk seen this session — the "flattened" half of the damped-oscillation motif
}

func riskScore(r event.RiskLevel) int {
	switch r {
	case event.RiskCritical:
		return 4
	case event.RiskHigh:
		return 3
	case event.RiskMedium:
		return 2
	default:
		return 1
	}
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	events, err := audit.ReadAll(s.cfg.AuditPath, audit.Filter{})
	if err != nil {
		http.Error(w, "reading audit log: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// A review caught a real bug in an earlier version of this function: it
	// sorted by each session's FIRST-seen position (reversed), which is
	// "most recently started," not "most recently active" — a session that
	// started earlier but resumed with a brand new, possibly alarming event
	// after a different session had already settled would be buried at the
	// bottom instead of surfaced first. ReadAll returns events in
	// chronological (file append) order, so each session's LAST-seen index
	// — tracked here on every event, not just the first — is what actually
	// determines recency once sessions interleave.
	ids := make([]string, 0, len(events))
	lastSeenIdx := make(map[string]int, len(events))
	byID := make(map[string]*sessionSpark, len(events))
	for i, e := range events {
		spark, ok := byID[e.SessionID]
		if !ok {
			spark = &sessionSpark{SessionID: e.SessionID, Actor: e.Actor}
			byID[e.SessionID] = spark
			ids = append(ids, e.SessionID)
		}
		spark.Points = append(spark.Points, riskScore(e.RiskLevel))
		lastSeenIdx[e.SessionID] = i
	}

	sort.Slice(ids, func(i, j int) bool {
		return lastSeenIdx[ids[i]] > lastSeenIdx[ids[j]]
	})
	if len(ids) > maxSessions {
		ids = ids[:maxSessions]
	}

	sessions := make([]sessionSpark, 0, len(ids))
	for _, id := range ids {
		spark := byID[id]
		if len(spark.Points) > maxPointsPerSession {
			spark.Points = spark.Points[len(spark.Points)-maxPointsPerSession:]
		}
		spark.Settled = isSettled(spark.Points)
		sessions = append(sessions, *spark)
	}

	writeJSON(w, sessions)
}

// isSettled reports whether the most recent point is at (or below) the
// lowest risk level seen earlier in the session — the visual/semantic
// signal docs/ux-dashboard-spec.md §1 calls "a session under policy",
// distinguishable from one "still spiking".
func isSettled(points []int) bool {
	if len(points) < 2 {
		return true
	}
	last := points[len(points)-1]
	for _, p := range points[:len(points)-1] {
		if last > p {
			return false
		}
	}
	return true
}
