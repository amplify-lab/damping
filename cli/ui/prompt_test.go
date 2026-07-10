package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/amplify-lab/damping/cli/i18n"
	"github.com/amplify-lab/damping/core/decision"
)

func TestTTYPrompter_AllowOnce(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader("a\n"), Out: &out}
	got := p.Confirm("rm -rf ~/", decision.Decision{Verdict: decision.Prompt, PolicyID: "destructive.rm_rf_protected"})
	if got.Verdict != decision.Allow || got.Persist {
		t.Fatalf("expected {Allow, Persist:false}, got %+v", got)
	}
}

func TestTTYPrompter_AlwaysAllow(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader("A\n"), Out: &out}
	got := p.Confirm("git status", decision.Decision{Verdict: decision.Prompt})
	if got.Verdict != decision.Allow || !got.Persist {
		t.Fatalf("expected {Allow, Persist:true}, got %+v", got)
	}
}

func TestTTYPrompter_DenyOnce(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader("d\n"), Out: &out}
	got := p.Confirm("rm -rf ~/", decision.Decision{Verdict: decision.Prompt})
	if got.Verdict != decision.Deny || got.Persist {
		t.Fatalf("expected {Deny, Persist:false}, got %+v", got)
	}
}

func TestTTYPrompter_AlwaysDeny(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader("D\n"), Out: &out}
	got := p.Confirm("rm -rf ~/", decision.Decision{Verdict: decision.Prompt})
	if got.Verdict != decision.Deny || !got.Persist {
		t.Fatalf("expected {Deny, Persist:true}, got %+v", got)
	}
}

func TestTTYPrompter_ReprocessesInvalidInput(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader("nonsense\na\n"), Out: &out}
	got := p.Confirm("rm -rf ~/", decision.Decision{Verdict: decision.Prompt})
	if got.Verdict != decision.Allow {
		t.Fatalf("expected Allow after re-prompting, got %+v", got)
	}
	if !strings.Contains(out.String(), "please enter") {
		t.Fatal("expected a re-prompt message for invalid input")
	}
}

func TestTTYPrompter_LowercaseAndUppercaseAreDistinct(t *testing.T) {
	// "a" and "A" must not be conflated — this is what distinguishes
	// "just this once" from "remember this" (see docs/cli-reference.md §12).
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader("ab\na\n"), Out: &out} // "ab" is invalid input, not "a" + stray "b"
	got := p.Confirm("rm -rf ~/", decision.Decision{Verdict: decision.Prompt})
	if got.Verdict != decision.Allow || got.Persist {
		t.Fatalf("expected the first valid line to be treated as plain 'a' (once), got %+v", got)
	}
}

func TestTTYPrompter_DeniesOnClosedInput(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader(""), Out: &out}
	got := p.Confirm("rm -rf ~/", decision.Decision{Verdict: decision.Prompt})
	if got.Verdict != decision.Deny {
		t.Fatalf("expected Deny when input closes unexpectedly, got %+v", got)
	}
}

// TestTTYPrompter_RendersInZhTW is the regression test for the 2026-07
// i18n expansion: Lang: i18n.LangZhTW must render the prompt's own chrome
// (Command/Rule/Reason labels, the [a]/[A]/[d]/[D] line, the invalid-input
// message) in Traditional Chinese, and translate a known rule's Reason via
// cli/i18n's lookup table rather than showing the raw (English)
// decision.Decision.Reason passed in.
func TestTTYPrompter_RendersInZhTW(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader("a\n"), Out: &out, Lang: i18n.LangZhTW}
	p.Confirm("rm -rf ~/", decision.Decision{
		Verdict:  decision.Prompt,
		PolicyID: "destructive.rm_rf_protected",
		Reason:   "the raw english reason text, should not appear verbatim",
	})
	got := out.String()
	for _, want := range []string{"指令", "規則", "理由", "只放行這一次", "只擋這一次"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected the zh-TW prompt to contain %q, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "the raw english reason text") {
		t.Errorf("expected the English Reason to be replaced by its zh-TW translation, got:\n%s", got)
	}
	if strings.Contains(got, "Command:") || strings.Contains(got, "Rule:") {
		t.Errorf("expected no English chrome labels in zh-TW mode, got:\n%s", got)
	}
}

// TestTTYPrompter_ZhTWFallsBackToEnglishReasonForUntranslatedRule ensures
// an untranslated rule id still shows *something* meaningful (the real
// English Reason) rather than an empty string, even while every other
// label around it renders in Chinese.
func TestTTYPrompter_ZhTWFallsBackToEnglishReasonForUntranslatedRule(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader("a\n"), Out: &out, Lang: i18n.LangZhTW}
	p.Confirm("some command", decision.Decision{
		Verdict:  decision.Prompt,
		PolicyID: "destructive.brand_new_rule_not_yet_translated",
		Reason:   "the real english reason for an untranslated rule",
	})
	if !strings.Contains(out.String(), "the real english reason for an untranslated rule") {
		t.Errorf("expected the English Reason as a fallback for an untranslated rule id, got:\n%s", out.String())
	}
}

// TestTTYPrompter_ReprocessesInvalidInputInZhTW pins that the re-prompt
// message (not just the initial chrome) is translated too.
func TestTTYPrompter_ReprocessesInvalidInputInZhTW(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader("nonsense\na\n"), Out: &out, Lang: i18n.LangZhTW}
	got := p.Confirm("rm -rf ~/", decision.Decision{Verdict: decision.Prompt})
	if got.Verdict != decision.Allow {
		t.Fatalf("expected Allow after re-prompting, got %+v", got)
	}
	if !strings.Contains(out.String(), "請輸入") {
		t.Fatal("expected a zh-TW re-prompt message for invalid input")
	}
}
