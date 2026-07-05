package policy

import "testing"

// TestHasRecursiveForce_CatchesEveryRealSpelling is a permanent regression
// test for a real bypass found via code review: an earlier version of
// hasRecursiveForce only matched the literal strings "-rf"/"-fr", so
// "rm -Rf /" — a very common way to type this — slipped through
// destructive.rm_rf_protected entirely. GNU rm accepts either case for the
// recursive flag; force is always lowercase.
func TestHasRecursiveForce_CatchesEveryRealSpelling(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"lowercase combined -rf", []string{"-rf", "/"}, true},
		{"lowercase combined -fr", []string{"-fr", "/"}, true},
		{"uppercase-R combined -Rf", []string{"-Rf", "/"}, true},
		{"uppercase-R combined -fR", []string{"-fR", "/"}, true},
		{"separate long flags", []string{"--recursive", "--force", "/"}, true},
		{"separate short flags", []string{"-r", "-f", "/"}, true},
		{"separate short flags uppercase R", []string{"-R", "-f", "/"}, true},
		{"cluster with extra flags", []string{"-vrf", "/"}, true},
		{"recursive only, no force", []string{"-r", "/"}, false},
		{"force only, no recursive", []string{"-f", "/"}, false},
		{"unrelated flags", []string{"-v", "/"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasRecursiveForce(tc.args); got != tc.want {
				t.Errorf("hasRecursiveForce(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

// TestIsWorldWritableOctalMode_CatchesLeadingDigitVariants is a permanent
// regression test: an earlier version only matched the literal string
// "777", missing "0777" (redundant leading zero) and modes with a leading
// sticky/setuid/setgid digit like "1777"/"2777"/"3777", all of which still
// grant world-write via the trailing 777.
func TestIsWorldWritableOctalMode_CatchesLeadingDigitVariants(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"777", true},
		{"0777", true},
		{"1777", true},
		{"2777", true},
		{"3777", true},
		{"755", false},
		{"", false},
		{"myfile777", false}, // not a valid octal mode token at all
	}
	for _, tc := range cases {
		if got := isWorldWritableOctalMode(tc.mode); got != tc.want {
			t.Errorf("isWorldWritableOctalMode(%q) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

func TestEvaluate_BlocksMixedCaseRmRfSpellings(t *testing.T) {
	e := loadDefaultEngine(t)
	cases := []struct {
		raw  string
		args []string
	}{
		{"rm -Rf /", []string{"-Rf", "/"}},
		{"rm -fR /", []string{"-fR", "/"}},
		{"rm -fr /", []string{"-fr", "/"}},
	}
	for _, tc := range cases {
		d := e.Evaluate(Facts{Raw: tc.raw, Command: "rm", Args: tc.args, Target: "/"})
		if d.PolicyID != "destructive.rm_rf_protected" {
			t.Errorf("evaluating %q: expected destructive.rm_rf_protected, got %q (verdict %v)", tc.raw, d.PolicyID, d.Verdict)
		}
	}
}

func TestEvaluate_BlocksChmodWithLeadingDigitMode(t *testing.T) {
	e := loadDefaultEngine(t)
	d := e.Evaluate(Facts{Raw: "chmod -R 1777 /var/www", Command: "chmod", Args: []string{"-R", "1777", "/var/www"}})
	if d.PolicyID != "destructive.chmod_777_recursive" {
		t.Fatalf("expected destructive.chmod_777_recursive, got %q (verdict %v)", d.PolicyID, d.Verdict)
	}
}
