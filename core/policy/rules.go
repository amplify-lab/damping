// Package policy's rule registry. The matcher functions themselves live in
// rules_shell.go (CLI/shell-command rules), rules_mcp.go (MCP tool-call
// rules), and rules_selfprotection.go (rules protecting Damping itself,
// e.g. an agent trying to disable it) — split by concern since each family
// grows independently (Phase 3 adds more MCP rules, Phase 6 adds memory-
// poisoning rules, without every contributor touching one giant file). This
// file holds only the shared registry and the cross-cutting Facts
// placeholders cli/shell relies on.
package policy

// matcher is the V1 hardcoded detection logic for one rule id. See
// docs/00-統一開發計畫（定案版）.md §四修正一 for why AST parsing alone
// (done upstream in cli/shell) does not remove the need for this explicit,
// testable, per-rule semantic layer — mvdan/sh gives structure, not intent.
type matcher func(Facts, Config) bool

// matchers is the V1 rule registry. Config.Validate rejects any configured
// rule id that has no entry here, so a typo in policy.yaml fails loudly at
// `damping doctor`/`damping policy validate` time instead of silently never
// firing.
var matchers = map[string]matcher{
	"destructive.rm_rf_protected":              matchRmRfProtected,
	"destructive.git_push_force":               matchGitPushForce,
	"destructive.sql_drop_truncate":            matchSQLDropTruncate,
	"destructive.chmod_777_recursive":          matchChmod777Recursive,
	"destructive.curl_pipe_sh_unallowlisted":   matchCurlPipeShUnallowlisted,
	"destructive.encoded_payload_pipe":         matchEncodedPayloadPipe,
	"destructive.proc_sandbox_bypass":          matchProcSandboxBypass,
	"destructive.dynamic_command_construction": matchDynamicCommandConstruction,
	"destructive.write_protected_path":         matchWriteProtectedPath,
	"mcp.write_tool_unscoped_identity":         matchMCPWriteToolUnscopedIdentity,
	"mcp.destructive_tool_call":                matchMCPDestructiveToolCall,
	"self_protection.damping_off_attempt":      matchDampingSelfDisableAttempt,

	// 2026-07 dangerous-command-coverage expansion (rules_expansion.go).
	"destructive.iac_destroy":             matchIACDestroy,
	"destructive.iac_apply_unreviewed":    matchIACApplyUnreviewed,
	"destructive.git_history_destructive": matchGitHistoryDestructive,
	"destructive.secret_exfiltration":     matchSecretExfiltration,

	// 2026-07 non-Bash attack-surface expansion (rules_configwrite.go).
	"destructive.agent_permission_escalation": matchAgentPermissionEscalation,
	"destructive.git_hook_write":              matchGitHookWrite,
	"destructive.npm_lifecycle_script_write":  matchNpmLifecycleScriptWrite,
}

// RedirectWritePlaceholder is what cli/shell sets Facts.Command to when it
// finds an output redirection (>, >>, >|, &>, &>>) rather than a command
// invocation — e.g. "echo key >> ~/.ssh/authorized_keys" is dangerous
// because of the redirect target, not because "echo" itself is a risky
// command name.
const RedirectWritePlaceholder = "<redirect-write>"

// DynamicCommandPlaceholder is what cli/shell sets Facts.Command to when the
// command name itself could not be statically resolved to a literal (e.g.
// "$(echo rm) -rf ~/" — mvdan/sh's Word.Lit() returns "" for anything other
// than a plain literal). core/policy never assumes an unresolvable command
// name is safe merely because it can't prove otherwise — see
// features/dangerous_command.feature's "command constructed dynamically"
// scenario.
const DynamicCommandPlaceholder = "<dynamic>"
