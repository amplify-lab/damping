package ui

import (
	"bytes"
	"strings"
	"testing"

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
