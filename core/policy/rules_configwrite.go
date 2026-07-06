package policy

import (
	"regexp"
	"strings"

	"github.com/amplify-lab/damping/core/event"
)

// This file holds the rules from the 2026-07 non-Bash attack-surface
// coverage expansion: cli/cmd/hook.go now also intercepts Claude Code's
// Write/Edit/MultiEdit tool calls (see cli/adapter/hook's Facts-building
// path for those), not just Bash — closing a gap this project's own
// earlier Phase 6 research had already flagged ("the real blocker is that
// cli/cmd/hook.go only observes Bash tool calls today"), independently
// reinforced by two real, verified CVEs: CVE-2025-53773 (GitHub Copilot —
// prompt injection writes chat.tools.autoApprove:true to
// .vscode/settings.json, then a subsequent terminal command runs
// unconfirmed) and CVE-2026-50549 (Cursor "DuneSlide" — a Write-tool
// symlink attack overwrites the sandbox executable itself). Cursor and
// Codex do not support blocking this class of action at all today — see
// docs/cli-reference.md §11's capability-matrix note — so these rules
// only ever fire for Claude Code in practice, not because they're written
// to be Claude-Code-specific, but because that's the only agent whose
// hook contract gives Damping a pre-write interception point to run in.

// --- destructive.agent_permission_escalation ---

// agentSettingsFileSuffixes are config-file paths (matched by suffix,
// since tool_input.file_path is typically absolute) whose content can
// change whether *future* tool calls require human confirmation at all —
// the exact class of file CVE-2025-53773 targeted, and directly analogous
// to this project's own real ~/.claude/settings.json, which already has a
// skipDangerousModePermissionPrompt key of the same shape.
var agentSettingsFileSuffixes = []string{
	".vscode/settings.json",
	".claude/settings.json",
	".claude/settings.local.json",
}

// dangerousPermissionEscalationPattern matches known keys, set to true,
// whose entire purpose is disabling a human-confirmation step. Not an
// exhaustive list of every possible such key in every possible editor/agent
// — a maintained, extensible list of known real cases, same "small,
// deliberately extensible demonstration" honesty this project already
// applies to cli/shell/facts.go's knownAliases table, not a claim of
// comprehensive coverage.
var dangerousPermissionEscalationPattern = regexp.MustCompile(`(?i)"(chat\.tools\.autoApprove|skipDangerousModePermissionPrompt|dangerouslySkipPermissions)"\s*:\s*true`)

func matchAgentPermissionEscalation(f Facts, _ Config) bool {
	if f.ActionType != event.ActionConfigWrite {
		return false
	}
	if !hasSuffixAmong(f.Target, agentSettingsFileSuffixes) {
		return false
	}
	return dangerousPermissionEscalationPattern.MatchString(f.Raw)
}

func hasSuffixAmong(target string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(target, s) {
			return true
		}
	}
	return false
}

// --- destructive.git_hook_write ---

func matchGitHookWrite(f Facts, _ Config) bool {
	if f.ActionType != event.ActionConfigWrite {
		return false
	}
	return strings.Contains(f.Target, ".git/hooks/") || strings.HasPrefix(f.Target, ".git/hooks/")
}

// --- destructive.npm_lifecycle_script_write ---

// npmLifecycleScriptPattern matches package.json keys that npm/pnpm/yarn
// run automatically at install time — the classic supply-chain execution
// vector (this project's own dangerous-command-coverage research already
// found real 2025-2026 campaigns, Nx s1ngularity and node-ipc, using
// exactly this mechanism, albeit via a published package rather than a
// Write tool call).
//
// Known, accepted limitation: a Write tool call's tool_input.content is
// always the file's *entire* new content — Damping has no access to the
// file's prior state to diff against, so re-saving an already-reviewed
// package.json that legitimately declares one of these scripts (a common,
// benign pattern — e.g. husky's "prepare": "husky install") re-triggers
// this rule every single time, not just on genuine introduction. Accepted
// v1 tradeoff, same class as rules_shell.go's hasUnscopedUpdateOrDelete
// false-negative disclosure — prompt-tier, not deny, specifically because
// of this.
var npmLifecycleScriptPattern = regexp.MustCompile(`(?i)"(postinstall|preinstall|prepare)"\s*:`)

func matchNpmLifecycleScriptWrite(f Facts, _ Config) bool {
	if f.ActionType != event.ActionConfigWrite {
		return false
	}
	if basename(f.Target) != "package.json" {
		return false
	}
	return npmLifecycleScriptPattern.MatchString(f.Raw)
}
