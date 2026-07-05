package decision

import "testing"

func TestDecision_Outcome_Unresolved(t *testing.T) {
	d := Decision{Verdict: Prompt}
	if got := d.Outcome(); got != Prompt {
		t.Fatalf("expected outcome %q before resolution, got %q", Prompt, got)
	}
}

func TestDecision_Resolve_PromptToAllow(t *testing.T) {
	d := Decision{Verdict: Prompt}
	if ok := d.Resolve(Allow); !ok {
		t.Fatal("expected Resolve to succeed on a Prompt decision")
	}
	if got := d.Outcome(); got != Allow {
		t.Fatalf("expected resolved outcome %q, got %q", Allow, got)
	}
}

func TestDecision_Resolve_RefusesNonPrompt(t *testing.T) {
	d := Decision{Verdict: Deny}
	if ok := d.Resolve(Allow); ok {
		t.Fatal("expected Resolve to refuse overwriting a non-Prompt decision")
	}
	if got := d.Outcome(); got != Deny {
		t.Fatalf("expected original outcome %q to be unchanged, got %q", Deny, got)
	}
}
