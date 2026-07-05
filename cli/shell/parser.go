// Package shell parses raw shell command text into policy.Facts using
// mvdan/sh's AST (mvdan.cc/sh/v3/syntax) rather than regular expressions —
// see docs/architecture.md §5 and docs/threat-model.md §3 for why this
// defeats formatting-based regex bypasses but does NOT, by itself, resolve
// aliases, decode runtime payloads, or understand /proc path semantics.
// Those gaps are covered by the explicit rules in core/policy plus the
// alias table in facts.go, not by the parser.
//
// This file is the AST traversal entry point (Analyze, walkStmts, walkCmd);
// facts.go turns a walked node into policy.Facts; literal.go resolves
// static word values.
package shell

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/amplify-lab/damping/core/policy"
)

// Analyze parses raw shell input and returns one policy.Facts per top-level
// command or pipeline found, descending into compound commands (if/while/
// for/function bodies, blocks, subshells) so a destructive command hidden
// inside a multi-line script is still discovered — see
// features/dangerous_command.feature, "hidden inside a multi-line script".
// It also descends into every command/process substitution wherever it
// appears (argument, assignment value, redirect target, here-string) and
// into any heredoc body addressed to a real shell interpreter, since both
// execute unconditionally at word-evaluation time regardless of how their
// output is used — see features/dangerous_command.feature, "command
// substitution used as an argument, not the command name" and "destructive
// command hidden inside a heredoc fed to a shell interpreter".
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
		collectRedirectSubstitutions(s, raw, out)
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

// shellReinterpretCommands are the interpreters that will actually execute a
// heredoc body as a shell script. A heredoc body is only re-parsed and
// walked when it's addressed to one of these — anything else (psql, python3,
// mail, ...) treats the heredoc as inert data, and walking it there would
// just produce false positives on ordinary non-shell payloads.
var shellReinterpretCommands = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
}

// collectRedirectSubstitutions finds command/process substitution hidden in
// a redirect target (including process substitution used as a write target,
// "echo hi > >(rm -rf ~)", and here-strings, "cat <<< \"$(rm -rf ~)\"") and
// walks it the same way an argument would be. It also handles heredoc
// bodies (Redir.Hdoc): any substitution embedded in an unquoted heredoc is
// walked unconditionally, and if the receiving command is a real shell
// interpreter, the whole heredoc body is re-parsed and walked as its own
// script — see features/dangerous_command.feature, "destructive command
// hidden inside a heredoc fed to a shell interpreter".
func collectRedirectSubstitutions(s *syntax.Stmt, raw string, out *[]policy.Facts) {
	var cmdName string
	if c, ok := s.Cmd.(*syntax.CallExpr); ok && len(c.Args) > 0 {
		cmdName, _ = staticWordValue(c.Args[0])
	}
	for _, r := range s.Redirs {
		if r.Word != nil {
			walkWordSubstitutions(r.Word, raw, out)
		}
		if r.Hdoc == nil {
			continue
		}
		walkWordSubstitutions(r.Hdoc, raw, out)
		if !shellReinterpretCommands[cmdName] {
			continue
		}
		body, ok := staticWordValue(r.Hdoc)
		if !ok || strings.TrimSpace(body) == "" {
			continue
		}
		parser := syntax.NewParser(syntax.KeepComments(true))
		file, err := parser.Parse(strings.NewReader(body), "")
		if err != nil {
			continue
		}
		walkStmts(file.Stmts, raw, out)
	}
}

// walkWordSubstitutions descends into a word looking for embedded command or
// process substitution — no matter where the word appears (argument,
// assignment value, redirect target) — and walks the embedded statements as
// if they were their own top-level script.
func walkWordSubstitutions(w *syntax.Word, raw string, out *[]policy.Facts) {
	if w == nil {
		return
	}
	for _, part := range w.Parts {
		walkPartSubstitutions(part, raw, out)
	}
}

func walkPartSubstitutions(part syntax.WordPart, raw string, out *[]policy.Facts) {
	switch p := part.(type) {
	case *syntax.CmdSubst:
		walkStmts(p.Stmts, raw, out)
	case *syntax.ProcSubst:
		walkStmts(p.Stmts, raw, out)
	case *syntax.DblQuoted:
		for _, inner := range p.Parts {
			walkPartSubstitutions(inner, raw, out)
		}
	}
}

func walkCmd(cmd syntax.Command, raw string, out *[]policy.Facts) {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		// Command/process substitution executes at word-evaluation time
		// regardless of how its output is used — a destructive command
		// hidden in "echo $(rm -rf ~)" or "x=$(rm -rf ~)" runs whether or
		// not "echo"/"x" ever consumes the result. See
		// features/dangerous_command.feature, "command substitution used as
		// an argument, not the command name".
		for _, a := range c.Assigns {
			if a.Value != nil {
				walkWordSubstitutions(a.Value, raw, out)
			}
		}
		for _, a := range c.Args {
			walkWordSubstitutions(a, raw, out)
		}
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
