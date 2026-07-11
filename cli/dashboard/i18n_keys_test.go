package dashboard

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// This package's own doc comment on cli/i18n/i18n_test.go's
// TestRuleReasonsZhTW_CoversEveryDefaultRule enforces exactly this kind of
// key-parity for rule translations; index.html's inline en/zh UI-chrome
// dicts (see its own I18N doc comment) had no equivalent check at all, so a
// key added to one language and forgotten in the other would silently fall
// back to the English string (t()'s own fallback) rather than fail loudly
// anywhere.
//
// i18nDictMarker delimits the three boundaries this test depends on inside
// the embedded HTML: the start of the "en" dict, the start of the "zh"
// dict, and the close of the whole I18N object literal. These are the
// literal indentation+braces index.html's own <script> actually uses (two-
// space-indented object literals directly under `const I18N = {`) — chosen
// deliberately strict (exact substring markers, not a loose regex) so a
// restructuring of that literal fails this test's own extraction instead of
// silently extracting zero keys and passing vacuously.
const (
	i18nEnMarker    = "\n  en: {\n"
	i18nZhMarker    = "\n  zh: {\n"
	i18nCloseMarker = "\n  },\n};"
)

// i18nKeyPattern matches one `key: "value"` pair anywhere in a dict block —
// applied with FindAllStringSubmatch rather than per-line, since index.html
// packs several pairs on one source line in places (e.g. "enforcement_label:
// ..., policy_label: ..., agents_label: ...,"). The (?:^|,) anchor is
// required, not cosmetic: several of the dict's own English values end in a
// word followed by ":" right before their closing quote (e.g.
// `"Session:"`, `"Run this yourself:"`) — without anchoring a real key to
// the start of a line or right after a preceding pair's comma, those
// in-value substrings match the same `\w+:\s*"` shape and get misread as
// keys of their own.
var i18nKeyPattern = regexp.MustCompile(`(?m)(?:^|,)[ \t]*(\w+):\s*"`)

// extractI18NDicts locates and parses index.html's en/zh I18N dicts,
// failing the test loudly (rather than returning an empty/partial result)
// if any expected marker is missing or a block yields zero keys — both
// signal the extraction itself broke, not that a dict is genuinely empty.
func extractI18NDicts(t *testing.T, html string) (en, zh map[string]bool) {
	t.Helper()

	enStart := strings.Index(html, i18nEnMarker)
	if enStart == -1 {
		t.Fatalf("could not find the %q marker that starts the en I18N dict in index.html — has its structure changed?", i18nEnMarker)
	}
	zhStart := strings.Index(html, i18nZhMarker)
	if zhStart == -1 || zhStart < enStart {
		t.Fatalf("could not find the %q marker that starts the zh I18N dict (after en) in index.html — has its structure changed?", i18nZhMarker)
	}
	closeIdx := strings.Index(html[zhStart:], i18nCloseMarker)
	if closeIdx == -1 {
		t.Fatalf("could not find the %q marker that closes the I18N object literal in index.html — has its structure changed?", i18nCloseMarker)
	}
	zhEnd := zhStart + closeIdx

	enBlock := html[enStart+len(i18nEnMarker) : zhStart]
	zhBlock := html[zhStart+len(i18nZhMarker) : zhEnd]

	return extractKeys(t, "en", enBlock), extractKeys(t, "zh", zhBlock)
}

func extractKeys(t *testing.T, lang, block string) map[string]bool {
	t.Helper()
	matches := i18nKeyPattern.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		t.Fatalf("extracted zero keys from the %s I18N dict block — extraction regex or index.html's structure is likely broken, this is not a genuinely empty dict", lang)
	}
	keys := make(map[string]bool, len(matches))
	for _, m := range matches {
		keys[m[1]] = true
	}
	return keys
}

// TestI18NDicts_HaveIdenticalKeySets is the regression guard: every key in
// the en dict must have a zh counterpart and vice versa, mirroring
// cli/i18n/i18n_test.go's TestRuleReasonsZhTW_CoversEveryDefaultRule for
// this package's own (much smaller, UI-chrome-only) translation surface.
func TestI18NDicts_HaveIdenticalKeySets(t *testing.T) {
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("reading embedded index.html: %v", err)
	}
	en, zh := extractI18NDicts(t, string(data))

	var missingInZh, missingInEn []string
	for k := range en {
		if !zh[k] {
			missingInZh = append(missingInZh, k)
		}
	}
	for k := range zh {
		if !en[k] {
			missingInEn = append(missingInEn, k)
		}
	}
	sort.Strings(missingInZh)
	sort.Strings(missingInEn)

	if len(missingInZh) > 0 {
		t.Errorf("keys present in en but missing from zh: %v", missingInZh)
	}
	if len(missingInEn) > 0 {
		t.Errorf("keys present in zh but missing from en: %v", missingInEn)
	}
}
