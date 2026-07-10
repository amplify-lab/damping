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
		return unescapeUnquoted(p.Value), true
	case *syntax.SglQuoted:
		// Single quotes suppress every escape: the value is already literal.
		return p.Value, true
	case *syntax.DblQuoted:
		var sb strings.Builder
		for _, inner := range p.Parts {
			if l, ok := inner.(*syntax.Lit); ok {
				sb.WriteString(unescapeDoubleQuoted(l.Value))
				continue
			}
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

// unescapeUnquoted and unescapeDoubleQuoted resolve backslash escapes the way
// the shell does, because mvdan/sh's AST deliberately preserves a literal's
// *source* text rather than its evaluated value — `sh -c "sh -c \"rm -rf ~/\""`
// yields a Lit whose Value still contains the backslashes.
//
// Without this, any argument carrying an escape resolved to a string the shell
// would never actually pass. That was invisible while cli/shell only ever
// re-parsed heredoc bodies, but it silently defeated the 2026-07 fix that
// re-parses an interpreter's -c script: one level of nesting worked, and every
// level below it re-parsed backslash-laden garbage that either failed to parse
// or produced operands like `"rm` instead of `rm`. See
// TestAnalyze_ReinterpretationIsDepthBounded and
// TestStaticWordValue_ResolvesShellEscapes.

// unescapeUnquoted applies unquoted-context rules: a backslash escapes any
// following character, and a backslash before a newline is a line
// continuation (both characters vanish). A trailing backslash stays literal.
func unescapeUnquoted(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			sb.WriteByte(s[i])
			continue
		}
		i++
		if s[i] != '\n' {
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// dblQuoteEscapable are the only characters a backslash escapes inside double
// quotes; before anything else the backslash is an ordinary literal character.
var dblQuoteEscapable = map[byte]bool{'$': true, '`': true, '"': true, '\\': true, '\n': true}

func unescapeDoubleQuoted(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) || !dblQuoteEscapable[s[i+1]] {
			sb.WriteByte(s[i])
			continue
		}
		i++
		if s[i] != '\n' {
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

func extractDomain(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}
