package i18n

import (
	"reflect"
	"testing"

	"github.com/amplify-lab/damping/cli/policies"
	"github.com/amplify-lab/damping/core/policy"
)

func TestResolveLang_ExplicitValuesPassThrough(t *testing.T) {
	if got := ResolveLang("en"); got != LangEN {
		t.Errorf("expected LangEN, got %q", got)
	}
	if got := ResolveLang("zh-TW"); got != LangZhTW {
		t.Errorf("expected LangZhTW, got %q", got)
	}
}

func TestResolveLang_AutoDetectsFromLANG(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LANG", "zh_TW.UTF-8")
	if got := ResolveLang(""); got != LangZhTW {
		t.Errorf("expected LANG=zh_TW.UTF-8 to resolve to LangZhTW, got %q", got)
	}
}

func TestResolveLang_LCAllTakesPriorityOverLANG(t *testing.T) {
	t.Setenv("LC_ALL", "zh_TW.UTF-8")
	t.Setenv("LANG", "en_US.UTF-8")
	if got := ResolveLang(""); got != LangZhTW {
		t.Errorf("expected LC_ALL to win over a conflicting LANG, got %q", got)
	}
}

func TestResolveLang_DefaultsToEnglishWhenUnset(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LANG", "")
	if got := ResolveLang(""); got != LangEN {
		t.Errorf("expected LangEN when neither ui_language nor $LANG/$LC_ALL suggest otherwise, got %q", got)
	}
}

func TestResolveLang_DefaultsToEnglishForNonChineseLocale(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LANG", "fr_FR.UTF-8")
	if got := ResolveLang(""); got != LangEN {
		t.Errorf("expected a non-Chinese locale to default to LangEN, got %q", got)
	}
}

func TestReason_TranslatesKnownRuleInZhTW(t *testing.T) {
	got := Reason("destructive.rm_rf_protected", LangZhTW, "the english fallback")
	if got == "the english fallback" {
		t.Fatal("expected a real translation, got the fallback")
	}
	if got == "" {
		t.Fatal("expected a non-empty translation")
	}
}

func TestReason_FallsBackToEnglishForEnglishLang(t *testing.T) {
	got := Reason("destructive.rm_rf_protected", LangEN, "the english fallback")
	if got != "the english fallback" {
		t.Errorf("expected the English fallback for LangEN, got %q", got)
	}
}

func TestReason_FallsBackToEnglishForUnknownRuleID(t *testing.T) {
	got := Reason("destructive.brand_new_rule_not_translated_yet", LangZhTW, "the english fallback")
	if got != "the english fallback" {
		t.Errorf("expected the English fallback for an untranslated rule id, got %q", got)
	}
}

// TestRuleReasonsZhTW_CoversEveryDefaultRule is the regression guard this
// package's own doc comment promises: every rule id actually shipped in
// cli/policies/default.yaml must have a ruleReasonsZhTW entry. A missing
// translation doesn't break anything at runtime (Reason falls back to
// English), but this test makes the gap visible at build time instead of
// silently shipping English-only rows forever.
func TestRuleReasonsZhTW_CoversEveryDefaultRule(t *testing.T) {
	cfg, err := policy.ParseConfig([]byte(policies.Default))
	if err != nil {
		t.Fatalf("parsing the shipped default policy: %v", err)
	}
	var missing []string
	for _, r := range cfg.Rules {
		if _, ok := ruleReasonsZhTW[r.ID]; !ok {
			missing = append(missing, r.ID)
		}
	}
	if len(missing) > 0 {
		t.Errorf("missing zh-TW translations for %d rule(s): %v", len(missing), missing)
	}
}

// TestRuleReasonsZhTW_NoStaleEntries is the mirror check: an entry here
// for a rule id that no longer exists in default.yaml (renamed or
// removed) is dead weight worth cleaning up, not a bug, but worth
// surfacing rather than silently accumulating forever.
func TestRuleReasonsZhTW_NoStaleEntries(t *testing.T) {
	cfg, err := policy.ParseConfig([]byte(policies.Default))
	if err != nil {
		t.Fatalf("parsing the shipped default policy: %v", err)
	}
	known := make(map[string]bool, len(cfg.Rules))
	for _, r := range cfg.Rules {
		known[r.ID] = true
	}
	for id := range ruleReasonsZhTW {
		if !known[id] {
			t.Errorf("ruleReasonsZhTW has a stale entry for %q, which is no longer in default.yaml", id)
		}
	}
}

func TestPromptStrings_BothLanguagesHaveEveryFieldPopulated(t *testing.T) {
	for _, lang := range []Lang{LangEN, LangZhTW} {
		s := Prompt(lang)
		v := reflect.ValueOf(s)
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).String() == "" {
				t.Errorf("Prompt(%q).%s is empty", lang, v.Type().Field(i).Name)
			}
		}
	}
}

func TestPromptStrings_FallsBackToEnglishForUnknownLang(t *testing.T) {
	got := Prompt(Lang("fr"))
	want := Prompt(LangEN)
	if got != want {
		t.Errorf("expected an unrecognized Lang to fall back to English prompt strings, got %+v", got)
	}
}
