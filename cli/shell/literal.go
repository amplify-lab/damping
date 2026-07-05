package shell

import (
	"net/url"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// literalArgs resolves each word to its static string value, or "" if the
// word cannot be resolved without executing it (contains a parameter
// expansion, command substitution, arithmetic expansion, process
// substitution, or extended glob). Note this is deliberately broader than
// Word.Lit(), which only recognizes words made up of bare *Lit parts and
// would incorrectly treat any quoted string (e.g. `"DROP TABLE users;"`) as
// unresolvable, even though quoting alone introduces no dynamic behavior.
func literalArgs(words []*syntax.Word) []string {
	out := make([]string, len(words))
	for i, w := range words {
		if v, ok := staticWordValue(w); ok {
			out[i] = v
		}
	}
	return out
}

// staticWordValue returns a word's literal string value if every part of it
// is statically known (plain text or quoted text), and false if any part
// requires runtime evaluation (variable/command/arithmetic substitution,
// process substitution, or extended globs).
func staticWordValue(w *syntax.Word) (string, bool) {
	var sb strings.Builder
	for _, part := range w.Parts {
		s, ok := staticPartValue(part)
		if !ok {
			return "", false
		}
		sb.WriteString(s)
	}
	return sb.String(), true
}

func staticPartValue(part syntax.WordPart) (string, bool) {
	switch p := part.(type) {
	case *syntax.Lit:
		return p.Value, true
	case *syntax.SglQuoted:
		return p.Value, true
	case *syntax.DblQuoted:
		var sb strings.Builder
		for _, inner := range p.Parts {
			s, ok := staticPartValue(inner)
			if !ok {
				return "", false
			}
			sb.WriteString(s)
		}
		return sb.String(), true
	default:
		// *ParamExp, *CmdSubst, *ArithmExp, *ProcSubst, *ExtGlob: not
		// resolvable without actually executing the shell — see
		// docs/threat-model.md §3.
		return "", false
	}
}

func extractDomain(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}
