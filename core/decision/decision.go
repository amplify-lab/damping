// Package decision defines the policy engine's decision output: allow, deny,
// or prompt, plus the metadata needed to explain and audit that decision. It
// has no dependency on core/event so core/policy can depend on it without
// pulling in the full audit schema.
package decision

// Verdict is the resolved outcome of a policy decision.
type Verdict string

const (
	Allow  Verdict = "allow"
	Deny   Verdict = "deny"
	Prompt Verdict = "prompt"
)

// Decision is what core/policy.Evaluate returns for a given ActionEvent. A
// Prompt verdict is later resolved to Allow or Deny by a human at the TTY
// (see cli/ui) — ResolvedVerdict captures that outcome so the audit trail
// ends up with one coherent record instead of two disjoint ones.
type Decision struct {
	Verdict         Verdict `json:"verdict"`
	ResolvedVerdict Verdict `json:"resolved_verdict,omitempty"`
	PolicyID        string  `json:"policy_id,omitempty"`
	Reason          string  `json:"reason,omitempty"`
	// Degraded marks a decision made under an internal Damping failure
	// (parser crash, corrupt policy file, hook timeout) rather than a real
	// policy match. See docs/threat-model.md §6.
	Degraded bool `json:"degraded,omitempty"`
}

// Outcome returns ResolvedVerdict if the decision has been resolved by a
// human, otherwise the original Verdict.
func (d Decision) Outcome() Verdict {
	if d.ResolvedVerdict != "" {
		return d.ResolvedVerdict
	}
	return d.Verdict
}

// Resolve records a human's answer to a Prompt decision. It is a no-op
// (returns false) if the decision was not actually a Prompt, so callers can't
// accidentally overwrite a decision the policy engine already settled.
func (d *Decision) Resolve(v Verdict) bool {
	if d.Verdict != Prompt {
		return false
	}
	d.ResolvedVerdict = v
	return true
}
