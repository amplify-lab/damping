package policy

import "strings"

// This file holds the rules from the 2026-07 agent-asset-protection
// expansion: commands that destroy the AI agent's *own* installed assets —
// skills, plugins, marketplaces, per-project session/memory state — in bulk.
// The user-facing harm is a different shape from the rest of the destructive
// family: nothing outside the agent breaks, but accumulated curation
// (installed skill sets, user-authored skills, conversation history) is gone
// with no undo, and the agent that did it keeps running as if nothing
// happened.
//
// Grounding evidence, verified for real rather than assumed:
//   - vercel-labs/skills issue #604 (2026-03-13, fixed by PR #609): the
//     skills CLI's `remove --all -g` treated every directory in the shared
//     global skills store (~/.agents/skills) as tool-owned and deleted it —
//     including user-authored skills its own lockfile never tracked. The
//     user's skills were only recoverable because their content happened to
//     survive in unrelated session logs.
//   - The skills CLI's own README documents `--all` as shorthand for
//     `--skill '*' --agent '*' -y`: every skill, every agent, and -y so no
//     confirmation prompt is ever shown. No undo/backup mechanism is
//     documented for any remove operation.
//   - vercel-labs/skills issue #287 (fixed by PR #297): even a *single*
//     named removal used to delete the shared source directory other agents
//     still symlinked to. Deliberately NOT matched here — single-item
//     removal is routine lifecycle management (see the false-positive-guard
//     scenarios in features/dangerous_command.feature), and the underlying
//     bug is fixed upstream; it's cited as evidence this command family's
//     blast radius is real, not as something this rule fires on.
//   - `claude plugin marketplace remove`, `claude plugin uninstall --prune`,
//     and `claude project purge --all` were each verified against the real
//     Claude Code CLI's own --help output (v2.1.206), not guessed from
//     docs: marketplace removal cascades to everything sourced from that
//     marketplace; --prune also removes auto-installed dependencies;
//     `project purge --all` deletes transcripts/tasks/file-history for
//     *every* project (its --dry-run flag is the sanctioned safe preview,
//     so that form is excluded below, same as cargo publish --dry-run).
//
// Known, disclosed v1 gaps (bypasses welcome as regression scenarios, per
// CONTRIBUTING.md): a list-then-loop composition ("for s in $(skills list
// ...); do skills remove $s -y; done") evaluates as N independent
// single-item Facts — each iteration still lands in the audit log as its
// own record, so the mass removal is reconstructable after the fact even
// though no single call trips this rule; and a scoped/aliased package
// spelling (`npx @some-scope/skills ...`) does not resolve to the known
// package name "skills".

// --- destructive.agent_asset_mass_removal ---

func matchAgentAssetMassRemoval(f Facts, _ Config) bool {
	switch f.Command {
	case "skills":
		return isSkillsMassRemove(f.Args)
	case "npx", "bunx":
		pkg, rest := runnerWrappedInvocation(f.Args)
		return pkg == "skills" && isSkillsMassRemove(rest)
	case "pnpm", "yarn":
		// Only the dlx subcommand runs a fetched package the way npx does —
		// `pnpm remove <dep>` / `yarn remove <dep>` are ordinary project
		// dependency management and must never reach the skills check.
		if len(f.Args) == 0 || f.Args[0] != "dlx" {
			return false
		}
		pkg, rest := runnerWrappedInvocation(f.Args[1:])
		return pkg == "skills" && isSkillsMassRemove(rest)
	case "claude":
		return isClaudeAssetMassRemoval(f.Args)
	}
	return false
}

// isSkillsMassRemove reports whether a skills-CLI argument list is a *mass*
// removal: the remove/rm subcommand in fixed first position (style of
// matchKubectlBulkDelete's rest[0] check — skills' own CLI grammar puts the
// subcommand first) combined with either the --all shorthand or a '*'
// wildcard operand (which catches the longhand --skill '*' / --agent '*'
// spellings --all expands to, and the one-skill-every-agent fan-out shape).
// A single named removal with no wildcard never matches.
func isSkillsMassRemove(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] != "remove" && args[0] != "rm" {
		return false
	}
	rest := args[1:]
	return containsArg(rest, "--all") || containsArg(rest, "*")
}

// runnerValueFlags are npx/bunx flags that consume the following argument
// as their value, so that value must not be mistaken for the package word —
// the same problem dampingSubcommand already solves for damping's --config.
var runnerValueFlags = map[string]bool{"-p": true, "--package": true, "-c": true, "--call": true}

// runnerWrappedInvocation resolves which package an npx/bunx invocation
// actually runs: the first argument that is neither a flag nor a
// value-consuming flag's value, with any @version/@tag suffix stripped
// ("skills@latest" -> "skills"). A scoped name ("@scope/pkg") keeps its
// leading "@" and therefore never equals a bare known package name — the
// disclosed gap in the file header. The token-is-a-preceding-flag's-value
// check looks back exactly one position, mirroring policy.rego's
// is_runner_flag_value so the two engines stay byte-for-byte identical.
func runnerWrappedInvocation(args []string) (string, []string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if i > 0 && runnerValueFlags[args[i-1]] {
			continue
		}
		name := a
		if idx := strings.Index(a, "@"); idx > 0 {
			name = a[:idx]
		}
		return name, args[i+1:]
	}
	return "", nil
}

// isClaudeAssetMassRemoval matches the three Claude Code CLI shapes whose
// blast radius is inherently bulk (all verified against the real CLI's
// --help, v2.1.206 — see the file header): removing a marketplace (cascades
// to every plugin sourced from it, with rm as a documented alias),
// uninstalling a plugin with --prune (also removes auto-installed
// dependencies; uninstall's documented alias is remove), and purging state
// for every project at once. Deliberately unmatched: `claude mcp remove
// <name>` (no bulk flag exists in its grammar — it is the single most
// common, explicitly-safe MCP lifecycle action), plain single-plugin
// uninstall, and `claude project purge` scoped to one project — all
// routine, plausibly user-requested operations whose flagging would be
// exactly the false-positive nagging that gets a tool like this
// uninstalled (docs/threat-model.md).
func isClaudeAssetMassRemoval(args []string) bool {
	if len(args) < 2 {
		return false
	}
	switch args[0] {
	case "plugin", "plugins":
		switch args[1] {
		case "marketplace":
			return len(args) >= 3 && (args[2] == "remove" || args[2] == "rm")
		case "uninstall", "remove":
			return containsArg(args[2:], "--prune")
		}
		return false
	case "project":
		if args[1] != "purge" {
			return false
		}
		rest := args[2:]
		return containsArg(rest, "--all") && !containsArg(rest, "--dry-run")
	}
	return false
}

// --- destructive.find_delete_protected ---

// matchFindDeleteProtected covers the same catastrophic-target set as
// matchRmRfProtected — home/root, configured protected paths, well-known
// system directories — reached through `find <path> -delete` instead of rm.
// Before this rule, Command=="find" was matched by zero rules, so any
// protected path was silently deletable through this one verb. The helper
// checks and their precedence order are matchRmRfProtected's verbatim
// (protected wins outright; a recognized-regenerable/temp target is only
// carved out of the system-critical check, so `find /var/tmp/cache -delete`
// stays quiet while `find /var/lib -delete` does not).
//
// Known, disclosed v1 gaps, same class as matchKubectlBulkDelete's
// documented positional assumption: a path operand placed *after* the
// expression ("find -delete ~/.claude" — not find's documented grammar, but
// GNU find tolerates it) slips past findPathOperands, and the destructive
// action buried inside -exec's own argv ("find ~/.claude -exec rm -rf {} ;")
// is a structurally different problem left for a future rule.
func matchFindDeleteProtected(f Facts, cfg Config) bool {
	if f.Command != "find" {
		return false
	}
	if !containsArg(f.Args, "-delete") {
		return false
	}
	for _, target := range findPathOperands(f.Args) {
		// A path operand the parser could not resolve to a literal collapses
		// to "" (an unquoted "$HOME/.claude" is a *syntax.ParamExp, resolvable
		// only by executing the shell). `-delete` is destructive by
		// construction, so an unprovable target gets the same confirmation a
		// known-protected one does — the reasoning behind
		// DynamicCommandPlaceholder for command names, applied to a path.
		// Accepted cost: `find "$BUILD_DIR" -delete` prompts too.
		if target == "" {
			return true
		}
		if isFilesystemOrHomeRoot(target) || inProtectedPaths(target, cfg.ProtectedPaths) {
			return true
		}
		if isRecognizedSafeRmTarget(target) {
			continue
		}
		if isSystemCriticalPath(target) {
			return true
		}
	}
	return false
}

// findPathOperands returns find's starting-point path operands: every
// argument before the first "-"-prefixed token, where find's own expression
// begins. Mirrored exactly in policy.rego's find_path_operands.
func findPathOperands(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") && a != "-" {
			break
		}
		out = append(out, a)
	}
	return out
}
