// Package i18n is damping's minimal, additive translation layer for the
// two places a running binary displays a rule's Reason text directly to a
// human, rather than just logging it: the TTY confirmation prompt
// (cli/ui) and `damping policy test`'s output.
//
// This is deliberately NOT part of core/policy. The policy engine's
// Decision.Reason is always English, always canonical — the audit log
// (core/audit), compliance reports (core/compliance), and
// core/policy/opa_equivalence_test.go's byte-identical-Reason assertion
// between the Go-native and OPA engines all depend on that never
// changing. Translation happens here, only at the last-mile render step,
// with an unconditional fallback to the original English Reason for any
// rule id this package doesn't (yet) have a translation for — a
// partially-translated rule set never breaks, it just shows English for
// whatever's missing. See CONTRIBUTING.md: every new rule needs both a
// blocks-scenario and an allow-scenario before it merges; it does NOT
// need a Chinese translation before it merges, by the same "additive,
// never blocking" principle.
package i18n

import (
	"os"
	"strings"
)

// Lang identifies a supported display language. The zero value ("") is
// never a real selection — callers resolve it via ResolveLang first.
type Lang string

const (
	LangEN   Lang = "en"
	LangZhTW Lang = "zh-TW"
)

// ResolveLang normalizes a raw ui_language config value (policy.Config's
// UILanguage field, or "" if unset/never configured) into a concrete Lang.
// An explicit "en"/"zh-TW" is used as-is. An empty/unrecognized value
// falls back to auto-detecting from $LANG/$LC_ALL — the standard POSIX
// locale environment variables — so a machine already configured for a
// Chinese locale gets sensible Chinese output by default even before
// `damping init` has ever asked, and so does a genuinely non-interactive
// install (CI, a piped `curl | sh` follow-up) that never had the chance to
// ask at all. Defaults to English when neither variable suggests
// otherwise.
func ResolveLang(configured string) Lang {
	switch Lang(configured) {
	case LangEN, LangZhTW:
		return Lang(configured)
	}
	for _, envVar := range []string{"LC_ALL", "LANG"} {
		if v := os.Getenv(envVar); strings.HasPrefix(strings.ToLower(v), "zh") {
			return LangZhTW
		}
	}
	return LangEN
}

// Reason returns the translated description for policyID in lang, or
// fallback (the Decision's own Reason field — always the canonical
// English text) if lang is English or no translation exists for that
// rule id yet.
func Reason(policyID string, lang Lang, fallback string) string {
	if lang != LangZhTW {
		return fallback
	}
	if zh, ok := ruleReasonsZhTW[policyID]; ok {
		return zh
	}
	return fallback
}

// PromptStrings is the small, fixed set of UI-chrome labels the TTY
// confirmation prompt renders around a rule's Reason — see cli/ui's
// Confirm. Unlike Reason above, these have no "fallback if missing"
// concept: every field here is used unconditionally by cli/ui, so both
// language maps must stay complete (checked by i18n_test.go).
//
// CommandLabel/RuleLabel/ReasonLabel each carry their own trailing colon
// and any alignment padding, rather than cli/ui appending a bare ": " —
// the original English copy hand-aligns "Command:"/"Rule:   "/"Reason: "
// into a column, and that specific padding only makes sense for those
// specific English words' lengths; a translated label controls its own
// spacing (or, as here, a fullwidth "：" that already reads cleanly with
// no extra padding needed) instead of inheriting English's.
type PromptStrings struct {
	Intercepted  string // the "⚠ Damping intercepted..." header
	CommandLabel string
	RuleLabel    string
	ReasonLabel  string
	AllowLine    string // the full "[a] Allow once   [A] Always allow..." line
	DenyLine     string // the full "[d] Deny once    [D] Always deny..." line
	InvalidInput string
}

var promptStringsByLang = map[Lang]PromptStrings{
	LangEN: {
		Intercepted:  "⚠  Damping intercepted a destructive command",
		CommandLabel: "Command: ",
		RuleLabel:    "Rule:    ",
		ReasonLabel:  "Reason:  ",
		AllowLine:    "[a] Allow once   [A] Always allow this exact command",
		DenyLine:     "[d] Deny once    [D] Always deny this exact command",
		InvalidInput: "please enter 'a', 'A', 'd', or 'D'",
	},
	LangZhTW: {
		Intercepted:  "⚠  Damping 攔截了一個具破壞性的指令",
		CommandLabel: "指令：",
		RuleLabel:    "規則：",
		ReasonLabel:  "理由：",
		AllowLine:    "[a] 只放行這一次   [A] 永遠放行這個指令",
		DenyLine:     "[d] 只擋這一次     [D] 永遠擋掉這個指令",
		InvalidInput: "請輸入 'a'、'A'、'd' 或 'D'",
	},
}

// Prompt returns the UI-chrome label set for lang, falling back to English
// for a Lang this package doesn't recognize (defensive only — ResolveLang
// never actually returns anything outside LangEN/LangZhTW).
func Prompt(lang Lang) PromptStrings {
	if s, ok := promptStringsByLang[lang]; ok {
		return s
	}
	return promptStringsByLang[LangEN]
}
