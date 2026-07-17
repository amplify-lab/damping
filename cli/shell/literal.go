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

// callWords resolves a call expression's words for rule evaluation: the
// command word (index 0) strictly statically — an unresolvable command name
// must keep collapsing to "" so factsFromWords surfaces it as
// DynamicCommandPlaceholder — and every argument word through argWordValue,
// so a word-leading plain $HOME reaches the rules as the canonical `~`
// spelling instead of vanishing into "".
func callWords(words []*syntax.Word) []string {
	out := make([]string, len(words))
	for i, w := range words {
		if i == 0 {
			if v, ok := staticWordValue(w); ok {
				out[i] = v
			}
			continue
		}
		if v, ok := argWordValue(w); ok {
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
	return wordValue(w, resolveStatic)
}

// argWordValue resolves an *argument* word the way staticWordValue does, with
// one extension: a word that *begins* with a plain expansion of HOME —
// `$HOME`, `"$HOME"`, `${HOME}` — resolves to the policy layer's canonical
// home spelling `~` (so `$HOME/.cache` becomes `~/.cache`). $HOME is the one
// variable whose meaning the shell itself fixes (`~` expands to it by
// definition), so this stays deterministic and environment-independent —
// nothing is read from the process env, which the policy engines must never
// depend on (see core/policy's tempRootPrefixes doc comment).
//
// Deliberately NOT applied to the command-name position: a command word that
// cannot be statically resolved must keep collapsing to "" so factsFromWords
// surfaces it as DynamicCommandPlaceholder — resolving `$HOME/bin/x` there
// would instead present an unmatchable literal command name and silently
// bypass destructive.dynamic_command_construction.
//
// This exists because of the 2026-07 GPT-5.6 Codex incident (see
// docs/threat-model.md §3 and README.md's incident table): the agent tried to
// re-point $HOME at a temp directory and deleted the real $HOME instead.
// `rm -rf $HOME` used to collapse its operand to "", landing in the
// *medium*-tier unrecognized-path rule — the exact tier an unattended
// operator reasonably auto-allows via noninteractive_prompt_fallback.
func argWordValue(w *syntax.Word) (string, bool) {
	return wordValue(w, resolveHomeCanonical)
}

// scriptWordValue resolves a word that some already-parsed command will
// re-execute as shell source text (a `-c` script, an `eval` argument, a
// heredoc body fed to a shell interpreter). Unlike staticWordValue it keeps a
// plain parameter expansion as its literal source spelling (`$NAME` /
// `${NAME}`) instead of giving up — the text is about to be re-parsed by
// Analyze, which turns that spelling back into the same *syntax.ParamExp and
// judges it in argument position (`bash -c "rm -rf $HOME"` therefore reaches
// the rm rules as `rm -rf $HOME`, not as one opaque unresolvable string).
// Anything genuinely runtime-only ($(cmd), ${x:-y}, arithmetic) still fails
// resolution, and the caller surfaces the script as
// DynamicCommandPlaceholder rather than assuming it safe.
func scriptWordValue(w *syntax.Word) (string, bool) {
	return wordValue(w, resolveParamSource)
}

// paramResolver is a policy for what a plain (unmodified, un-indexed,
// un-sliced) parameter expansion resolves to, position-aware: atWordStart is
// true only for the word's very first part (including the first part inside
// a leading double-quoted section).
type paramResolver func(p *syntax.ParamExp, atWordStart bool) (string, bool)

func resolveStatic(*syntax.ParamExp, bool) (string, bool) { return "", false }

func resolveHomeCanonical(p *syntax.ParamExp, atWordStart bool) (string, bool) {
	if atWordStart && isPlainParam(p) && p.Param.Value == "HOME" {
		return "~", true
	}
	return "", false
}

func resolveParamSource(p *syntax.ParamExp, _ bool) (string, bool) {
	if !isPlainParam(p) {
		return "", false
	}
	if p.Short {
		return "$" + p.Param.Value, true
	}
	return "${" + p.Param.Value + "}", true
}

// isPlainParam mirrors mvdan/sh's unexported ParamExp.simple(): a bare $name
// or ${name} with no operator, index, slice, replacement, or expansion —
// anything more needs runtime evaluation and stays unresolvable.
func isPlainParam(p *syntax.ParamExp) bool {
	return p.Param != nil && p.Flags == nil &&
		!p.Excl && !p.Length && !p.Width && !p.IsSet &&
		p.NestedParam == nil && p.Index == nil &&
		len(p.Modifiers) == 0 && p.Slice == nil &&
		p.Repl == nil && p.Names == 0 && p.Exp == nil
}

func wordValue(w *syntax.Word, resolve paramResolver) (string, bool) {
	var sb strings.Builder
	for i, part := range w.Parts {
		s, ok := partValue(part, resolve, i == 0)
		if !ok {
			return "", false
		}
		sb.WriteString(s)
	}
	return sb.String(), true
}

func partValue(part syntax.WordPart, resolve paramResolver, atWordStart bool) (string, bool) {
	switch p := part.(type) {
	case *syntax.Lit:
		return unescapeUnquoted(p.Value), true
	case *syntax.SglQuoted:
		// Single quotes suppress every escape: the value is already literal.
		return p.Value, true
	case *syntax.DblQuoted:
		var sb strings.Builder
		for i, inner := range p.Parts {
			if l, ok := inner.(*syntax.Lit); ok {
				sb.WriteString(unescapeDoubleQuoted(l.Value))
				continue
			}
			s, ok := partValue(inner, resolve, atWordStart && i == 0)
			if !ok {
				return "", false
			}
			sb.WriteString(s)
		}
		return sb.String(), true
	case *syntax.ParamExp:
		return resolve(p, atWordStart)
	default:
		// *CmdSubst, *ArithmExp, *ProcSubst, *ExtGlob: not resolvable
		// without actually executing the shell — see docs/threat-model.md §3.
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
