package policy

import "strings"

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
// Scoped narrowly to `damping off` actually occupying the subcommand
// position — not just the literal token "off" appearing anywhere in the
// argument list, and not every `damping` subcommand (status/doctor/log are
// harmless diagnostics an agent may legitimately be asked to run). This
// was a real false-positive bypass fixed after a review: a bare "off" token
// used as a flag's *value* elsewhere (e.g. "damping log --actor off", or a
// wrapped MCP server's own flag passed through "damping mcp wrap -- server
// --telemetry off") used to trip this critical/deny rule even though the
// agent never actually ran `damping off`. Broader self-protection concerns
// (e.g. policy file tampering via other means) are covered separately, see
// docs/threat-model.md §8.
func matchDampingSelfDisableAttempt(f Facts, _ Config) bool {
	if f.Command != "damping" {
		return false
	}
	sub, ok := dampingSubcommand(f.Args)
	return ok && sub == "off"
}

// dampingSubcommand returns the first argument that occupies the
// subcommand position — as opposed to a global flag or a global flag's
// value — so a bare "off" token elsewhere in the argument list (a flag
// value passed through to a wrapped MCP server, "damping mcp wrap --
// some-server --telemetry off", or a filter value on an unrelated
// subcommand, "damping log --actor off") is never mistaken for the actual
// `damping off` subcommand. Mirrors policy.rego's damping_subcommand
// exactly. Only "damping"'s one global persistent flag (--config, which
// takes a value) is special-cased; any other leading "-"-prefixed token is
// treated as a boolean-ish flag with no separate value.
func dampingSubcommand(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--config" {
			i++ // skip the flag's value too
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a, true
	}
	return "", false
}
