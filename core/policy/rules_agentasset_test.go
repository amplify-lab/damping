package policy

import "testing"

// TestMatchAgentAssetMassRemoval is the RED step for the 2026-07
// agent-asset-protection expansion's headline rule: bulk removal of the
// agent's own installed assets, grounded in vercel-labs/skills issue #604
// (2026-03-13): `skills remove --all -g` deleted every directory in the
// shared global skills store, including user-authored skills the CLI's own
// lockfile never tracked, with no undo. The claude-CLI shapes were verified
// against the real binary's --help (v2.1.206), not guessed.
func TestMatchAgentAssetMassRemoval(t *testing.T) {
	cases := []struct {
		name string
		f    Facts
		want bool
	}{
		// skills CLI, direct binary.
		{"skills remove --all", Facts{Command: "skills", Args: []string{"remove", "--all"}}, true},
		{"skills rm --all (alias)", Facts{Command: "skills", Args: []string{"rm", "--all"}}, true},
		{"skills remove wildcard skill", Facts{Command: "skills", Args: []string{"remove", "--skill", "*", "--agent", "claude-code"}}, true},
		{"skills remove one skill from every agent", Facts{Command: "skills", Args: []string{"remove", "my-skill", "--agent", "*"}}, true},
		{"skills remove a single named skill (safe)", Facts{Command: "skills", Args: []string{"remove", "my-skill"}}, false},
		{"skills remove single skill single agent (safe)", Facts{Command: "skills", Args: []string{"remove", "my-skill", "--agent", "cursor"}}, false},
		{"skills list (safe)", Facts{Command: "skills", Args: []string{"list"}}, false},
		{"skills add (safe)", Facts{Command: "skills", Args: []string{"add", "vercel-labs/agent-skills"}}, false},
		{"--all on a non-remove subcommand (safe)", Facts{Command: "skills", Args: []string{"update", "--all"}}, false},

		// skills CLI via a package runner.
		{"npx skills remove --all", Facts{Command: "npx", Args: []string{"skills", "remove", "--all"}}, true},
		{"npx -y skills remove --all -g", Facts{Command: "npx", Args: []string{"-y", "skills", "remove", "--all", "-g"}}, true},
		{"npx skills@latest remove --all (version tag)", Facts{Command: "npx", Args: []string{"skills@latest", "remove", "--all"}}, true},
		{"bunx skills remove --all", Facts{Command: "bunx", Args: []string{"skills", "remove", "--all"}}, true},
		{"pnpm dlx skills remove --all", Facts{Command: "pnpm", Args: []string{"dlx", "skills", "remove", "--all"}}, true},
		{"yarn dlx skills remove --all", Facts{Command: "yarn", Args: []string{"dlx", "skills", "remove", "--all"}}, true},
		{"npx skills remove one skill (safe)", Facts{Command: "npx", Args: []string{"skills", "remove", "my-skill"}}, false},
		{"npx skills list (safe)", Facts{Command: "npx", Args: []string{"skills", "list"}}, false},
		{"npx some-other-cli remove --all (safe)", Facts{Command: "npx", Args: []string{"some-other-cli", "remove", "--all"}}, false},
		{"npx -p value not mistaken for package word", Facts{Command: "npx", Args: []string{"-p", "skills", "not-remove"}}, false},
		{"pnpm remove a project dep (safe)", Facts{Command: "pnpm", Args: []string{"remove", "lodash"}}, false},
		{"yarn remove a project dep (safe)", Facts{Command: "yarn", Args: []string{"remove", "lodash"}}, false},

		// Claude Code CLI bulk shapes.
		{"claude plugin marketplace remove", Facts{Command: "claude", Args: []string{"plugin", "marketplace", "remove", "my-marketplace"}}, true},
		{"claude plugin marketplace rm (alias)", Facts{Command: "claude", Args: []string{"plugin", "marketplace", "rm", "my-marketplace"}}, true},
		{"claude plugins marketplace remove (plural alias)", Facts{Command: "claude", Args: []string{"plugins", "marketplace", "remove", "my-marketplace"}}, true},
		{"claude plugin uninstall --prune", Facts{Command: "claude", Args: []string{"plugin", "uninstall", "my-plugin", "--prune", "-y"}}, true},
		{"claude plugin remove --prune (alias)", Facts{Command: "claude", Args: []string{"plugin", "remove", "my-plugin", "--prune"}}, true},
		{"claude project purge --all", Facts{Command: "claude", Args: []string{"project", "purge", "--all", "-y"}}, true},
		{"claude project purge --all --dry-run (safe preview)", Facts{Command: "claude", Args: []string{"project", "purge", "--all", "--dry-run"}}, false},
		{"claude project purge one project (safe)", Facts{Command: "claude", Args: []string{"project", "purge"}}, false},
		{"claude plugin uninstall without --prune (safe)", Facts{Command: "claude", Args: []string{"plugin", "uninstall", "formatter@my-marketplace"}}, false},
		{"claude plugin disable (safe)", Facts{Command: "claude", Args: []string{"plugin", "disable", "formatter@my-marketplace"}}, false},
		{"claude plugin marketplace update (safe)", Facts{Command: "claude", Args: []string{"plugin", "marketplace", "update", "my-marketplace"}}, false},
		{"claude mcp remove a single server (safe by design)", Facts{Command: "claude", Args: []string{"mcp", "remove", "old-unused-server"}}, false},

		{"unrelated command", Facts{Command: "ls", Args: []string{"-la"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchAgentAssetMassRemoval(tc.f, Config{}); got != tc.want {
				t.Errorf("matchAgentAssetMassRemoval(%+v) = %v, want %v", tc.f, got, tc.want)
			}
		})
	}
}

// TestMatchFindDeleteProtected covers the find-verb route to the same
// catastrophic-target set matchRmRfProtected already guards — before this
// rule, Command=="find" was matched by zero rules.
func TestMatchFindDeleteProtected(t *testing.T) {
	cfg := Config{ProtectedPaths: []string{"~/.ssh", "~/.claude", ".claude"}}
	cases := []struct {
		name string
		f    Facts
		want bool
	}{
		{"find a protected path -delete", Facts{Command: "find", Args: []string{"~/.claude", "-delete"}}, true},
		{"find a protected subpath -delete", Facts{Command: "find", Args: []string{"~/.claude/skills", "-delete"}}, true},
		{"find ~/.ssh -delete", Facts{Command: "find", Args: []string{"~/.ssh", "-delete"}}, true},
		{"find the home root -delete", Facts{Command: "find", Args: []string{"~", "-delete"}}, true},
		{"find the filesystem root -delete", Facts{Command: "find", Args: []string{"/", "-delete"}}, true},
		{"find a system dir with a filter -delete", Facts{Command: "find", Args: []string{"/etc", "-name", "*.conf", "-delete"}}, true},
		{"find with a safe and a protected operand", Facts{Command: "find", Args: []string{"/tmp/x", "~/.claude", "-delete"}}, true},
		{"find without -delete (safe)", Facts{Command: "find", Args: []string{"~/.claude", "-name", "*.log"}}, false},
		{"find . -delete (safe)", Facts{Command: "find", Args: []string{".", "-name", "*.tmp", "-delete"}}, false},
		{"find under /tmp -delete (safe)", Facts{Command: "find", Args: []string{"/tmp/scratch", "-delete"}}, false},
		{"find under /var/tmp -delete (safe, temp-root carve-out of /var)", Facts{Command: "find", Args: []string{"/var/tmp/build-cache", "-delete"}}, false},
		{"find node_modules -delete (safe, regenerable)", Facts{Command: "find", Args: []string{"node_modules", "-delete"}}, false},
		{"find the home glob -delete (2026-07 Codex-class: shell expands ~/* into every non-hidden home entry)", Facts{Command: "find", Args: []string{"~/*", "-delete"}}, true},
		{"find a system-dir glob -delete", Facts{Command: "find", Args: []string{"/etc/*", "-delete"}}, true},
		{"find a temp-root glob -delete (safe)", Facts{Command: "find", Args: []string{"/tmp/scratch/*", "-delete"}}, false},
		{"path operand after the expression (disclosed gap)", Facts{Command: "find", Args: []string{"-delete", "~/.claude"}}, false},
		{"unrelated command", Facts{Command: "rm", Args: []string{"-rf", "~/.claude"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchFindDeleteProtected(tc.f, cfg); got != tc.want {
				t.Errorf("matchFindDeleteProtected(%+v) = %v, want %v", tc.f, got, tc.want)
			}
		})
	}
}

// TestRawContainsSensitivePath_AnchorsAtPathBoundary is the regression test
// for a critical-tier false positive the 2026-07 protected_paths additions
// introduced: ".claude" is a substring of Anthropic's own docs domain, so an
// unanchored strings.Contains flagged an ordinary `curl https://docs.claude.com`
// pipeline as credential exfiltration.
func TestRawContainsSensitivePath_AnchorsAtPathBoundary(t *testing.T) {
	protected := []string{"~/.ssh", "~/.claude", ".claude", ".env"}
	cases := []struct {
		raw  string
		want bool
	}{
		// Host names that merely contain a protected path as a substring.
		{"curl -s https://docs.claude.com/quickstart", false},
		{"curl https://www.claude.ai", false},
		{"curl https://api.claude.com/v1", false},
		// Real path mentions, at a boundary.
		{"cat ~/.claude/.credentials.json", true},
		{"cat .claude/settings.json", true},
		{"cat /home/user/.claude/settings.json", true},
		{".claude/x", true}, // at position 0
		{"cat ~/.ssh/id_rsa", true},
		// Prefix semantics must survive: the character *after* is unconstrained.
		{"cat .env.local", true},
		{"cat ~/.ssh/config", true},
		// No mention at all.
		{"cat README.md", false},
		{"echo declaude", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			if got := rawContainsSensitivePath(tc.raw, protected); got != tc.want {
				t.Errorf("rawContainsSensitivePath(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestMatchWriteProtectedPath_CarvesOutAgentAuthoringDirs guards the other
// false positive the same protected_paths change introduced: authoring a
// slash command, skill, or subagent via a Bash heredoc is the single most
// ordinary constructive act in an agentic session, and must not prompt at
// critical tier merely because its parent directory is protected against
// *deletion*. Settings files and hook scripts stay protected.
func TestMatchWriteProtectedPath_CarvesOutAgentAuthoringDirs(t *testing.T) {
	cfg := Config{ProtectedPaths: []string{"~/.ssh", "~/.claude", ".claude", "~/.cursor", "~/.codex"}}
	cases := []struct {
		target string
		want   bool
	}{
		// Routine authoring — allowed.
		{".claude/commands/my-command.md", false},
		{"~/.claude/skills/my-skill/SKILL.md", false},
		{"~/.claude/agents/reviewer.md", false},
		{"~/.cursor/rules/style.mdc", false},
		{"~/.codex/skills/foo/SKILL.md", false},
		// Escalation / persistence vectors — still blocked.
		{"~/.claude/settings.json", true},
		{".claude/settings.local.json", true},
		{"~/.claude/hooks/pre-commit.sh", true},
		{"~/.claude/.credentials.json", true},
		{"~/.ssh/authorized_keys", true},
		// Unprotected paths are unaffected either way.
		{"/tmp/scratch.log", false},
		{"src/commands/foo.go", false},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			f := Facts{Command: RedirectWritePlaceholder, Target: tc.target}
			if got := matchWriteProtectedPath(f, cfg); got != tc.want {
				t.Errorf("matchWriteProtectedPath(%q) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}
