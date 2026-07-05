// Package shell parses raw shell command text into policy.Facts using
// mvdan/sh's AST (mvdan.cc/sh/v3/syntax) rather than regular expressions —
// see docs/architecture.md §5 and docs/threat-model.md §3 for why this
// defeats formatting-based regex bypasses but does NOT, by itself, resolve
// aliases, decode runtime payloads, or understand /proc path semantics.
// Those gaps are covered by the explicit rules in core/policy plus the
// alias table in this package, not by the parser.
package shell

import (
	"fmt"
	"net/url"
	"strings"

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

// Analyze parses raw shell input and returns one policy.Facts per top-level
// command or pipeline found, descending into compound commands (if/while/
// for/function bodies, blocks, subshells) so a destructive command hidden
// inside a multi-line script is still discovered — see
// features/dangerous_command.feature, "hidden inside a multi-line script".
func Analyze(raw string) ([]policy.Facts, error) {
	parser := syntax.NewParser(syntax.KeepComments(true))
	file, err := parser.Parse(strings.NewReader(raw), "")
	if err != nil {
		return nil, fmt.Errorf("shell: parsing: %w", err)
	}
	var out []policy.Facts
	walkStmts(file.Stmts, raw, &out)
	return out, nil
}

func walkStmts(stmts []*syntax.Stmt, raw string, out *[]policy.Facts) {
	for _, s := range stmts {
		collectRedirectWrites(s, raw, out)
		if s.Cmd != nil {
			walkCmd(s.Cmd, raw, out)
		}
	}
}

// writeRedirOps are the redirection operators that write to a target path —
// as opposed to reading from one (RdrIn) or duplicating a descriptor.
var writeRedirOps = map[syntax.RedirOperator]bool{
	syntax.RdrOut:  true, // >
	syntax.AppOut:  true, // >>
	syntax.RdrClob: true, // >|
	syntax.RdrAll:  true, // &>
	syntax.AppAll:  true, // &>>
}

// collectRedirectWrites finds output redirections whose target can be
// resolved statically, independent of which command they're attached to —
// "echo key >> ~/.ssh/authorized_keys" is dangerous because of the redirect
// target, not because "echo" is a risky command name. See
// features/dangerous_command.feature, "Block writes to a protected path".
func collectRedirectWrites(s *syntax.Stmt, raw string, out *[]policy.Facts) {
	for _, r := range s.Redirs {
		if !writeRedirOps[r.Op] || r.Word == nil {
			continue
		}
		target, ok := staticWordValue(r.Word)
		if !ok || target == "" {
			continue
		}
		*out = append(*out, policy.Facts{
			Raw:     raw,
			Command: policy.RedirectWritePlaceholder,
			Target:  target,
		})
	}
}

func walkCmd(cmd syntax.Command, raw string, out *[]policy.Facts) {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		if f, ok := factsFromCall(c, raw); ok {
			*out = append(*out, f)
		}
	case *syntax.BinaryCmd:
		if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
			if f, ok := factsFromPipeline(c, raw); ok {
				*out = append(*out, f)
				return
			}
		}
		// && / || (or a pipe we couldn't fully interpret): each side may
		// still contain its own destructive call, so keep descending.
		if c.X != nil && c.X.Cmd != nil {
			walkCmd(c.X.Cmd, raw, out)
		}
		if c.Y != nil && c.Y.Cmd != nil {
			walkCmd(c.Y.Cmd, raw, out)
		}
	case *syntax.Block:
		walkStmts(c.Stmts, raw, out)
	case *syntax.Subshell:
		walkStmts(c.Stmts, raw, out)
	case *syntax.IfClause:
		for cur := c; cur != nil; cur = cur.Else {
			walkStmts(cur.Cond, raw, out)
			walkStmts(cur.Then, raw, out)
		}
	case *syntax.WhileClause:
		walkStmts(c.Cond, raw, out)
		walkStmts(c.Do, raw, out)
	case *syntax.ForClause:
		walkStmts(c.Do, raw, out)
	case *syntax.FuncDecl:
		if c.Body != nil && c.Body.Cmd != nil {
			walkCmd(c.Body.Cmd, raw, out)
		}
	}
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

// literalArgs resolves each word to its static string value, or "" if the
// word cannot be resolved without executing it (contains a parameter
// expansion, command substitution, arithmetic expansion, process
// substitution, or extended glob). Note this is deliberately broader than
// Word.Lit(), which only recognizes words made up of bare *Lit parts and
// would incorrectly treat any quoted string (e.g. `"DROP TABLE users;"`) as
// unresolvable, even though quoting alone introduces no dynamic behavior.
func literalArgs(words []*syntax.Word) []string {
	out := make([]string, len(words))
	for i, w := range words {
		if v, ok := staticWordValue(w); ok {
			out[i] = v
		}
	}
	return out
}

// staticWordValue returns a word's literal string value if every part of it
// is statically known (plain text or quoted text), and false if any part
// requires runtime evaluation (variable/command/arithmetic substitution,
// process substitution, or extended globs).
func staticWordValue(w *syntax.Word) (string, bool) {
	var sb strings.Builder
	for _, part := range w.Parts {
		s, ok := staticPartValue(part)
		if !ok {
			return "", false
		}
		sb.WriteString(s)
	}
	return sb.String(), true
}

func staticPartValue(part syntax.WordPart) (string, bool) {
	switch p := part.(type) {
	case *syntax.Lit:
		return p.Value, true
	case *syntax.SglQuoted:
		return p.Value, true
	case *syntax.DblQuoted:
		var sb strings.Builder
		for _, inner := range p.Parts {
			s, ok := staticPartValue(inner)
			if !ok {
				return "", false
			}
			sb.WriteString(s)
		}
		return sb.String(), true
	default:
		// *ParamExp, *CmdSubst, *ArithmExp, *ProcSubst, *ExtGlob: not
		// resolvable without actually executing the shell — see
		// docs/threat-model.md §3.
		return "", false
	}
}

func extractDomain(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}
