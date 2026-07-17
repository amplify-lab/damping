package policy

import (
	"testing"

	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
)

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

// TestIsUnderTempRoot is a permanent regression test for a real false
// positive: a developer's own disposable /tmp scratch directories (e.g. an
// agent's research working directory) were flagged destructive.rm_rf_protected
// purely because their basename wasn't in regenerableDirNames — an OS-managed
// scratch root is regenerable by construction, the same reasoning already
// applied to node_modules/build/dist, so rm -rf under one should be treated
// the same way regardless of what the leaf directory happens to be named.
func TestIsUnderTempRoot(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"/tmp", true},
		{"/tmp/scratch-research", true},
		{"/tmp/claude-1000/some-session/scratchpad", true},
		{"/var/tmp", true},
		{"/var/tmp/build-cache", true},
		{"/tmp-not-really", false}, // must not match by prefix alone
		{"/etc", false},
		{"/home/user/tmp", false}, // "tmp" as a path *segment* elsewhere is not the OS temp root
		{"", false},
	}
	for _, tc := range cases {
		if got := isUnderTempRoot(tc.target); got != tc.want {
			t.Errorf("isUnderTempRoot(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

func TestEvaluate_AllowsRmRfUnderOSTempRoot(t *testing.T) {
	e := loadDefaultEngine(t)
	cases := []string{
		"/tmp/scratch-research",
		"/tmp/claude-1000/some-session/scratchpad",
		"/var/tmp/build-cache",
	}
	for _, target := range cases {
		d := e.Evaluate(Facts{Raw: "rm -rf " + target, Command: "rm", Args: []string{"-rf", target}, Target: target})
		if d.Verdict != decision.Allow {
			t.Errorf("rm -rf %s: expected Allow, got verdict %v (rule %q)", target, d.Verdict, d.PolicyID)
		}
	}
}

// TestEvaluate_StillBlocksProtectedPathsThatLookLikeTempPaths guards against
// a naive prefix-only implementation swallowing an explicitly protected path
// that happens to sit inside /tmp — an operator-configured protected_paths
// entry must always win over the temp-root allowance.
func TestEvaluate_StillBlocksProtectedPathsThatLookLikeTempPaths(t *testing.T) {
	cfg, err := LoadConfig(defaultPolicyPath(t))
	if err != nil {
		t.Fatalf("loading default policy: %v", err)
	}
	cfg.ProtectedPaths = append(cfg.ProtectedPaths, "/tmp/do-not-touch")
	e := New(cfg)
	d := e.Evaluate(Facts{Raw: "rm -rf /tmp/do-not-touch", Command: "rm", Args: []string{"-rf", "/tmp/do-not-touch"}, Target: "/tmp/do-not-touch"})
	if d.PolicyID != "destructive.rm_rf_protected" {
		t.Fatalf("expected destructive.rm_rf_protected for an explicitly protected path, got %q (verdict %v)", d.PolicyID, d.Verdict)
	}
}

// TestIsSystemCriticalPath is a permanent regression test for the risk-tier
// split found via a real user's own audit-log review: every one of the 15
// real rm -rf interceptions Tim's own machine had logged turned out to be
// disposable scratch/research cleanup, not a genuine catastrophic delete —
// yet all 15 carried the same "critical" severity as an actual home-
// directory wipe, because the only two tiers this rule ever had were
// "explicitly known-safe" and "everything else is critical." The dividing
// line that actually matters is whether the target is a well-known,
// whole-filesystem-breaking system directory (this list) versus merely "not
// on the regenerable/temp-root allowlist" — see matchRmRfUnrecognizedPath
// for the latter, now a separate, lower-risk rule.
func TestIsSystemCriticalPath(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"/etc", true},
		{"/etc/nginx", true},
		{"/usr", true},
		{"/usr/local", true},
		{"/bin", true},
		{"/sbin", true},
		{"/lib", true},
		{"/lib64", true},
		{"/var", true},
		{"/boot", true},
		{"/opt", true},
		{"/root", true},
		{"/sys", true},
		{"/proc", true},
		{"/dev", true},
		{"/run", true},
		{"/srv", true},
		{"/tmp", false},        // OS scratch space, handled by isUnderTempRoot instead
		{"/home/alice", false}, // a user's own home dir isn't "the" home root check, but also isn't system-critical
		{"/etcetera", false},   // must not match by prefix alone
		{"./my-scratch-dir", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isSystemCriticalPath(tc.target); got != tc.want {
			t.Errorf("isSystemCriticalPath(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

// TestEvaluate_RmRfSystemCriticalPathStaysCritical confirms the risk-tier
// split didn't accidentally downgrade genuinely catastrophic targets — a
// system directory like /etc is just as unrecoverable as the home directory
// or filesystem root, even though (unlike those) it isn't hardcoded in
// isFilesystemOrHomeRoot.
func TestEvaluate_RmRfSystemCriticalPathStaysCritical(t *testing.T) {
	e := loadDefaultEngine(t)
	for _, target := range []string{"/etc", "/usr/local", "/var"} {
		d := e.Evaluate(Facts{Raw: "rm -rf " + target, Command: "rm", Args: []string{"-rf", target}, Target: target})
		if d.PolicyID != "destructive.rm_rf_protected" {
			t.Errorf("rm -rf %s: expected destructive.rm_rf_protected (critical), got %q (verdict %v)", target, d.PolicyID, d.Verdict)
		}
	}
}

// TestEvaluate_RmRfUnrecognizedPathIsMediumRiskNotCritical is the core
// regression guard for the risk-tier split: a target that's merely absent
// from the regenerable/temp-root allowlist — not home/root/protected/
// system-critical — is a real but much smaller concern than a catastrophic
// delete, and now gets its own lower-risk rule instead of inheriting
// destructive.rm_rf_protected's critical severity. This is what lets
// Config.NonInteractivePromptFallback actually help with exactly the kind
// of everyday scratch-directory cleanup a background agent runs constantly.
func TestEvaluate_RmRfUnrecognizedPathIsMediumRiskNotCritical(t *testing.T) {
	e := loadDefaultEngine(t)
	for _, target := range []string{"./my-scratch-research", ".scratch_research", "some-custom-folder"} {
		d := e.Evaluate(Facts{Raw: "rm -rf " + target, Command: "rm", Args: []string{"-rf", target}, Target: target})
		if d.PolicyID != "destructive.rm_rf_unrecognized_path" {
			t.Errorf("rm -rf %s: expected destructive.rm_rf_unrecognized_path, got %q (verdict %v)", target, d.PolicyID, d.Verdict)
		}
		if d.Risk != string(event.RiskMedium) {
			t.Errorf("rm -rf %s: expected medium risk, got %q", target, d.Risk)
		}
	}
}

// TestEvaluate_RmRfUnprovableTargetIsCritical: an operand cli/shell could not
// resolve to a literal collapses to "" — rm -rf is destructive by
// construction, so an unprovable target gets matchFindDeleteProtected's
// long-standing treatment, not the medium tier (which is exactly the tier a
// sane unattended noninteractive_prompt_fallback config auto-allows — and the
// 2026-07 GPT-5.6 Codex $HOME deletions happened in precisely that kind of
// unattended full-access run).
func TestEvaluate_RmRfUnprovableTargetIsCritical(t *testing.T) {
	e := loadDefaultEngine(t)
	d := e.Evaluate(Facts{Raw: `rm -rf "$BUILD_DIR"`, Command: "rm", Args: []string{"-rf", ""}, Target: ""})
	if d.PolicyID != "destructive.rm_rf_protected" {
		t.Fatalf("expected destructive.rm_rf_protected for an unprovable target, got %q (verdict %v)", d.PolicyID, d.Verdict)
	}
	if d.Risk != string(event.RiskCritical) {
		t.Fatalf("expected critical risk for an unprovable target, got %q", d.Risk)
	}
}

func TestStripTrailingSlashStar(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"~/*", "~/"},
		{"/*", "/"},
		{"/etc/*", "/etc/"},
		{"./build/*", "./build/"},
		{"~/*.log", "~/*.log"}, // a scoped glob is a bounded delete, not a directory wipe
		{"*", "*"},             // bare glob: cwd-relative, no directory to normalize to
		{"~/", "~/"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := stripTrailingSlashStar(tc.target); got != tc.want {
			t.Errorf("stripTrailingSlashStar(%q) = %q, want %q", tc.target, got, tc.want)
		}
	}
}

// TestEvaluate_RmRfGlobOfProtectedRootIsCritical: `rm -rf ~/*` empties the
// home directory exactly as `rm -rf ~/` does (minus dotfiles), and `rm -rf
// /*` is the classic spelling of a root wipe — both used to land in the
// medium unrecognized-path tier because the glob suffix matched no
// catastrophic-target literal.
func TestEvaluate_RmRfGlobOfProtectedRootIsCritical(t *testing.T) {
	e := loadDefaultEngine(t)
	for _, target := range []string{"~/*", "/*", "/etc/*", "~/.claude/*"} {
		d := e.Evaluate(Facts{Raw: "rm -rf " + target, Command: "rm", Args: []string{"-rf", target}, Target: target})
		if d.PolicyID != "destructive.rm_rf_protected" {
			t.Errorf("rm -rf %s: expected destructive.rm_rf_protected, got %q (verdict %v)", target, d.PolicyID, d.Verdict)
		}
	}
}

// TestEvaluate_RmRfGlobOfRegenerableStaysAllowed is the false-positive guard
// for the glob normalization: "<dir>/*" must land in the exact same
// regenerable/temp-root carve-outs "<dir>" itself already hits.
func TestEvaluate_RmRfGlobOfRegenerableStaysAllowed(t *testing.T) {
	e := loadDefaultEngine(t)
	for _, target := range []string{"./build/*", "node_modules/*", "/tmp/scratch/*"} {
		d := e.Evaluate(Facts{Raw: "rm -rf " + target, Command: "rm", Args: []string{"-rf", target}, Target: target})
		if d.Verdict != decision.Allow {
			t.Errorf("rm -rf %s: expected Allow, got verdict %v (rule %q)", target, d.Verdict, d.PolicyID)
		}
	}
}
