package policy

import "strings"

// matchesAnyPattern and matchGlobPattern implement the always_allow/
// always_deny pattern engine used by Engine.Evaluate — distinct from the
// per-rule matchers in rules_shell.go/rules_mcp.go, since these operate on
// user-authored patterns rather than a fixed rule id.

func matchesAnyPattern(patterns []string, f Facts) bool {
	for _, p := range patterns {
		if matchGlobPattern(p, f.Raw) {
			return true
		}
	}
	return false
}

// matchGlobPattern supports a trailing "*" as a prefix wildcard (e.g.
// "git status*"), which is the pattern vocabulary documented for
// hand-authored policy rules in docs/cli-reference.md §13. V1's automatic
// [A]/[D] prompt persistence (core/policy.AppendAlwaysPattern) only ever
// writes exact command text, never a wildcard — see docs/cli-reference.md
// §12.
func matchGlobPattern(pattern, s string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == s
}
