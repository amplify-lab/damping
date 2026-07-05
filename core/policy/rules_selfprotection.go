package policy

// matchDampingSelfDisableAttempt fires when the agent itself tries to run
// `damping off` via its own Bash tool call — the exact Ona-incident failure
// mode (see docs/threat-model.md §4): an agent discovering a safety layer
// and turning it off itself, with no human ever agreeing to that.
//
// A human running `damping off` directly at their own terminal never goes
// through this matcher at all — Damping only sees actions the agent routes
// through the hook (its own Bash tool calls), so this rule specifically
// closes the "agent does it instead" gap without restricting the human's
// own sanctioned path (`damping off` itself still works fine for a human;
// it's only denied when it arrives as an agent-issued shell command).
//
// Scoped narrowly to `damping ... off` for now — not every `damping`
// subcommand (status/doctor/log are harmless diagnostics an agent may
// legitimately be asked to run). Broader self-protection concerns (e.g.
// policy file tampering via other means) are covered separately, see
// docs/threat-model.md §8.
func matchDampingSelfDisableAttempt(f Facts, _ Config) bool {
	if f.Command != "damping" {
		return false
	}
	for _, a := range f.Args {
		if a == "off" {
			return true
		}
	}
	return false
}
