package compliance

import (
	"strings"
	"testing"
	"time"

	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

func TestReport_RenderHTML_IsWellFormedSelfContainedDocument(t *testing.T) {
	r := Generate(nil, true)
	html, err := r.RenderHTML()
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(html), "<!doctype html>") {
		t.Fatalf("expected a well-formed HTML document, got:\n%s", html[:min(200, len(html))])
	}
	if !strings.Contains(html, "<style>") {
		t.Fatal("expected inline <style>, not an external stylesheet — this file must be shareable standalone")
	}
	if strings.Contains(html, "<script") || strings.Contains(html, "http://") || strings.Contains(html, "https://") && !strings.Contains(html, "damping.dev") {
		// damping.dev may legitimately appear in disclosure prose; any other
		// http(s) reference (an external stylesheet, font, or script host)
		// would break the "self-contained, works offline" property this
		// report exists for — see docs/cli-reference.md's compliance-report
		// section for that requirement.
		t.Fatalf("expected no external script/network references, got:\n%s", html)
	}
}

// TestReport_RenderHTML_EscapesUntrustedFields is the security-critical
// test for this file's entire reason to exist as a separate renderer:
// RenderMarkdown/RenderText build output via raw fmt.Fprintf string
// interpolation, safe for their own formats but NOT safe for HTML — Target
// and Reason both flow from a real ActionEvent an adversarial agent session
// could have influenced (see docs/threat-model.md §3), so RenderHTML must
// use html/template's context-aware auto-escaping, never that same raw
// interpolation pattern.
func TestReport_RenderHTML_EscapesUntrustedFields(t *testing.T) {
	payload := `<script>alert(document.cookie)</script>`
	reasonPayload := `"><img src=x onerror=alert(1)>`
	events := []event.ActionEvent{
		mustEvent(t, time.Now(), "alice", "alice@bank.tw", event.ChannelCLI, payload, event.RiskCritical, "destructive.rm_rf_protected", decision.Deny, ""),
	}
	r := Generate(events, false)
	r.HighRiskEntries[0].Reason = reasonPayload
	html, err := r.RenderHTML()
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if strings.Contains(html, "<script>alert(document.cookie)</script>") {
		t.Fatalf("Target payload was NOT escaped — raw <script> tag reached the output:\n%s", html)
	}
	if strings.Contains(html, `onerror=alert(1)`) {
		t.Fatalf("Reason payload was NOT escaped — raw onerror attribute reached the output:\n%s", html)
	}
	// The escaped form must still be present somewhere (proving the content
	// rendered at all, just safely) — html/template escapes "<" as "&lt;".
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("expected the escaped form of the payload to appear, got:\n%s", html)
	}
}

func TestReport_RenderHTML_DisclosesDemoScopeLimits(t *testing.T) {
	r := Generate(nil, true)
	html, err := r.RenderHTML()
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	for _, want := range []string{"demo", "not an official", "Phase 5"} {
		if !strings.Contains(html, want) {
			t.Errorf("expected disclosure text containing %q, got:\n%s", want, html)
		}
	}
}

func TestReport_RenderHTML_NonDemoDoesNotClaimToBeDemo(t *testing.T) {
	r := Generate(nil, false)
	html, err := r.RenderHTML()
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if strings.Contains(html, "synthetic 30-day") {
		t.Fatalf("a real (non-demo) report must not claim to be built on synthetic data, got:\n%s", html)
	}
}

func TestReport_RenderHTML_EmptyHighRiskIsExplicit(t *testing.T) {
	r := Generate(nil, false)
	html, err := r.RenderHTML()
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if !strings.Contains(html, "No high-risk or critical actions occurred in this period.") {
		t.Fatalf("expected the explicit empty-state message, got:\n%s", html)
	}
}

func TestReport_RenderHTML_IncludesChartsWhenDataPresent(t *testing.T) {
	events := []event.ActionEvent{
		mustEvent(t, time.Now(), "alice", "alice@bank.tw", event.ChannelCLI, "rm -rf /prod", event.RiskCritical, "destructive.rm_rf_protected", decision.Deny, ""),
	}
	r := Generate(events, false)
	html, err := r.RenderHTML()
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if !strings.Contains(html, "<svg") {
		t.Fatalf("expected at least one inline SVG chart when there's data to chart, got:\n%s", html)
	}
	if !strings.Contains(html, "destructive.rm_rf_protected") {
		t.Fatalf("expected the top-rules chart to name the matched rule, got:\n%s", html)
	}
}
