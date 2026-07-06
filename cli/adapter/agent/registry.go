package agent

import "github.com/amplify-lab/damping/cli/paths"

// Agent describes one supported AI coding agent's hook integration — the
// single source of truth `damping init`/`doctor`/`status`/`dashboard` all
// iterate over now, instead of each hand-coding its own per-agent branch. A
// review found that exact duplication three separate times (docs/00 §七
// item 8) — adding a new agent meant editing at least four files by hand;
// adding one here (plus a cli/cmd/hook.go stdin-parsing branch, which is
// genuinely bespoke per agent and not consolidated by this registry) is
// now the only change most of those call sites need.
type Agent struct {
	// Name matches both the `--agent` flag value (`damping init --agent
	// claude-code`) and event.ActionEvent.Actor — the one identifier used
	// consistently across config, CLI flags, and the audit trail.
	Name string
	// DisplayName is the human-readable form used in doctor/status/init
	// output ("Claude Code", not "claude-code").
	DisplayName string
	// HookLabel names the specific hook event this agent registers, for
	// messages like "Registered PreToolUse hook in Claude Code" — agents
	// don't share one event name (Claude Code's is "PreToolUse", Cursor's
	// is "beforeShellExecution"), so this isn't inferable from Name alone.
	HookLabel string
	// ConfigPath returns where this agent's own hook config file lives.
	ConfigPath func() string
	// Install idempotently registers Damping's hook in the file at
	// ConfigPath(), preserving any unrelated content already there.
	Install func(path string, force bool) error
	// HasHook reports whether Damping's hook is currently registered.
	HasHook func(path string) (bool, error)
}

// Registry is every agent Damping currently supports, in the order
// `damping init --agent all` configures them and doctor/status/dashboard
// list them.
var Registry = []Agent{
	{
		Name:        "claude-code",
		DisplayName: "Claude Code",
		HookLabel:   "PreToolUse hook",
		ConfigPath:  paths.ClaudeSettings,
		Install:     InstallClaudeCodeHook,
		HasHook:     HasClaudeCodeHook,
	},
	{
		Name:        "cursor",
		DisplayName: "Cursor",
		HookLabel:   "beforeShellExecution hook",
		ConfigPath:  paths.CursorHooks,
		Install:     InstallCursorHook,
		HasHook:     HasCursorHook,
	},
	{
		Name:        "codex",
		DisplayName: "Codex",
		HookLabel:   "PreToolUse hook",
		ConfigPath:  paths.CodexConfig,
		Install:     InstallCodexHook,
		HasHook:     HasCodexHook,
	},
}

// ByName looks up a single agent by its Name (the --agent flag value).
func ByName(name string) (Agent, bool) {
	for _, a := range Registry {
		if a.Name == name {
			return a, true
		}
	}
	return Agent{}, false
}
