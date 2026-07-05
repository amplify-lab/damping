package shell

import (
	"mvdan.cc/sh/v3/syntax"

	"github.com/amplify-lab/damping/core/policy"
)

// knownAliases maps a small set of known-dangerous shell aliases to the
// command+leading-args they resolve to. mvdan/sh's syntax package does not
// expand aliases (only the opt-in interp interpreter does, which means
// actually executing — unacceptable for a pre-execution check), so this is
// a maintained, explicit lookup table instead. See docs/threat-model.md §3.
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

	return policy.Facts{
		Raw:     raw,
		Command: command,
		Args:    args,
		Target:  target,
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
