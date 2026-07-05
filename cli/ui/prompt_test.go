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
	if got != decision.Allow {
		t.Fatalf("expected Allow, got %v", got)
	}
}

func TestTTYPrompter_DenyOnce(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader("d\n"), Out: &out}
	got := p.Confirm("rm -rf ~/", decision.Decision{Verdict: decision.Prompt})
	if got != decision.Deny {
		t.Fatalf("expected Deny, got %v", got)
	}
}

func TestTTYPrompter_ReprocessesInvalidInput(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader("nonsense\na\n"), Out: &out}
	got := p.Confirm("rm -rf ~/", decision.Decision{Verdict: decision.Prompt})
	if got != decision.Allow {
		t.Fatalf("expected Allow after re-prompting, got %v", got)
	}
	if !strings.Contains(out.String(), "please enter") {
		t.Fatal("expected a re-prompt message for invalid input")
	}
}

func TestTTYPrompter_DeniesOnClosedInput(t *testing.T) {
	var out bytes.Buffer
	p := TTYPrompter{In: strings.NewReader(""), Out: &out}
	got := p.Confirm("rm -rf ~/", decision.Decision{Verdict: decision.Prompt})
	if got != decision.Deny {
		t.Fatalf("expected Deny when input closes unexpectedly, got %v", got)
	}
}
