package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amplify-lab/damping/core/decision"
)

const fixtureWithComments = `# top-level header comment — must survive
version: 1

rules:
  - id: destructive.rm_rf_protected
    description: test rule
    risk: critical
    action: prompt

# comment right before always_allow — must survive
always_allow: []
always_deny: []
`

func TestAppendAlwaysPattern_AppendsAndPreservesComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(fixtureWithComments), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := AppendAlwaysPattern(path, decision.Allow, "git status"); err != nil {
		t.Fatalf("AppendAlwaysPattern: %v", err)
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	if !strings.Contains(got, "git status") {
		t.Fatalf("expected the new pattern in the file, got:\n%s", got)
	}
	if !strings.Contains(got, "top-level header comment — must survive") {
		t.Fatalf("expected the header comment to survive the edit, got:\n%s", got)
	}
	if !strings.Contains(got, "comment right before always_allow — must survive") {
		t.Fatalf("expected the comment near always_allow to survive the edit, got:\n%s", got)
	}

	// The edited file must still parse as a valid policy config afterward.
	cfg, err := ParseConfig(out)
	if err != nil {
		t.Fatalf("edited file no longer parses as valid config: %v", err)
	}
	found := false
	for _, p := range cfg.AlwaysAllow {
		if p == "git status" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected \"git status\" in always_allow, got %v", cfg.AlwaysAllow)
	}
}

func TestAppendAlwaysPattern_AppendsToAlwaysDeny(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(fixtureWithComments), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppendAlwaysPattern(path, decision.Deny, "git push --force"); err != nil {
		t.Fatalf("AppendAlwaysPattern: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if len(cfg.AlwaysDeny) != 1 || cfg.AlwaysDeny[0] != "git push --force" {
		t.Fatalf("expected always_deny to contain the new pattern, got %v", cfg.AlwaysDeny)
	}
}

func TestAppendAlwaysPattern_IsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(fixtureWithComments), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppendAlwaysPattern(path, decision.Allow, "git status"); err != nil {
		t.Fatal(err)
	}
	if err := AppendAlwaysPattern(path, decision.Allow, "git status"); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, p := range cfg.AlwaysAllow {
		if p == "git status" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one copy of the pattern after appending twice, got %d", count)
	}
}

// The atomic-write behavior itself (temp file + rename, no leftover temp
// file, requested permissions applied, original content survives a failed
// partial write) is tested directly in core/atomicfile, which this file now
// delegates to — see atomicfile_test.go / atomicfile_unix_test.go.

func TestAppendAlwaysPattern_RejectsPromptVerdict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(fixtureWithComments), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppendAlwaysPattern(path, decision.Prompt, "whatever"); err == nil {
		t.Fatal("expected an error persisting a Prompt verdict, which is never itself a final answer")
	}
}

// TestAppendAlwaysPattern_RejectsPatternEndingInAsterisk is a regression
// test for a real silent-scope-broadening bug: an approved command like
// "rm -rf ./dist/*" (a realistic shell glob, not a hand-authored wildcard
// pattern) used to be persisted verbatim. On the very next reload,
// matchGlobPattern (patterns.go) treats any always_allow/always_deny entry
// ending in "*" as a prefix wildcard — so the human's one-time "always
// allow this exact command" choice would silently turn into "always allow
// anything starting with rm -rf ./dist/" the moment a fresh process reloaded
// the policy file, never re-confirmed.
func TestAppendAlwaysPattern_RejectsPatternEndingInAsterisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(fixtureWithComments), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppendAlwaysPattern(path, decision.Allow, "rm -rf ./dist/*"); err == nil {
		t.Fatal("expected an error persisting a pattern ending in \"*\", which would be reinterpreted as a wildcard on reload")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "dist/*") {
		t.Fatal("expected the rejected pattern to never be written to the policy file at all")
	}
}
