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
	walkStmts(file.Stmts, raw, &out, 0)
	return out, nil
}

// maxReinterpretDepth bounds how many times Analyze will re-parse a string
// that some already-parsed command would itself execute as shell (a heredoc
// body fed to `sh`, an `sh -c` script, an `eval` argument). Each such string
// is strictly shorter than the text it came from, so the recursion always
// terminates on its own — but only after a depth proportional to the input
// length, and Analyze runs on fully untrusted, adversarially-crafted input by
// design (see FuzzAnalyze's doc comment, and docs/threat-model.md §3). A
// deeply nested `sh -c "sh -c \"sh -c ...\""` payload would otherwise be able
// to exhaust the goroutine stack and panic the `damping hook` subprocess.
// Depth 8 is far beyond any real script's nesting and cheap to enforce.
const maxReinterpretDepth = 8

func walkStmts(stmts []*syntax.Stmt, raw string, out *[]policy.Facts, depth int) {
	for _, s := range stmts {
		walkStmt(s, raw, out, depth)
	}
}

func walkStmt(s *syntax.Stmt, raw string, out *[]policy.Facts, depth int) {
	if s == nil {
		return
	}
	collectRedirectWrites(s, raw, out)
	collectRedirectSubstitutions(s, raw, out, depth)
	if s.Cmd != nil {
		walkCmd(s.Cmd, raw, out, depth)
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
		// argWordValue, not staticWordValue: a redirect target is a path in
		// argument position, so a word-leading plain $HOME resolves to the
		// canonical `~` — `echo x >> $HOME/.ssh/authorized_keys` used to
		// collapse to an unresolvable target and skip interception entirely,
		// while the byte-identical `>> ~/.ssh/authorized_keys` was caught.
		target, ok := argWordValue(r.Word)
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
func collectRedirectSubstitutions(s *syntax.Stmt, raw string, out *[]policy.Facts, depth int) {
	var cmdName string
	if c, ok := s.Cmd.(*syntax.CallExpr); ok && len(c.Args) > 0 {
		// The receiving command is resolved through the same wrapper
		// unwrapping everything else uses, so "sudo bash <<EOF" reinterprets
		// its heredoc body exactly as a bare "bash <<EOF" already did.
		if words := unwrapCommandPrefixes(literalArgs(c.Args)); len(words) > 0 {
			cmdName = words[0]
		}
	}
	for _, r := range s.Redirs {
		if r.Word != nil {
			walkWordSubstitutions(r.Word, raw, out, depth)
		}
		if r.Hdoc == nil {
			continue
		}
		walkWordSubstitutions(r.Hdoc, raw, out, depth)
		if !shellReinterpretCommands[cmdName] {
			continue
		}
		// scriptWordValue, not staticWordValue: an unquoted heredoc body
		// containing a plain $HOME (or any plain $VAR) keeps its source
		// spelling and re-parses into the same expansion in argument
		// position — `bash <<EOF` + `rm -rf $HOME` used to make the body
		// unresolvable and skip reinterpretation entirely.
		body, ok := scriptWordValue(r.Hdoc)
		if !ok {
			// The shell interpreter will definitely execute this body, and it
			// cannot be recovered even as source text (it embeds command
			// substitution or a runtime-only expansion) — surface it the same
			// way an unresolvable -c script is, instead of assuming it safe.
			*out = append(*out, policy.Facts{Raw: raw, Command: policy.DynamicCommandPlaceholder})
			continue
		}
		reinterpretScript(body, raw, out, depth)
	}
}

// reinterpretScript re-parses a string that the surrounding command will
// itself execute as shell — a heredoc body fed to an interpreter, an
// `sh -c` script, an `eval` argument — and walks it as its own script, so a
// destructive command inside it is caught by the ordinary rules rather than
// hidden inside one opaque string literal. Depth-bounded; see
// maxReinterpretDepth.
func reinterpretScript(script, raw string, out *[]policy.Facts, depth int) {
	if depth >= maxReinterpretDepth || strings.TrimSpace(script) == "" {
		return
	}
	parser := syntax.NewParser(syntax.KeepComments(true))
	file, err := parser.Parse(strings.NewReader(script), "")
	if err != nil {
		return
	}
	walkStmts(file.Stmts, raw, out, depth+1)
}

// embeddedShellScripts returns the argument strings an already-unwrapped
// command will execute as shell code in its own right: an interpreter's
// `-c` script (`bash -c "rm -rf ~/"`, including clustered spellings like
// `bash -lc`) and everything `eval` is handed (`eval "rm -rf ~/"`, and the
// unquoted `eval rm -rf ~/`, whose words the shell re-joins before parsing).
// nodes are the AST words aligned index-for-index with words, so a script
// operand whose *value* couldn't be resolved can still be recovered as
// source text via scriptWordValue — `bash -c "rm -rf $HOME"` re-parses as
// `rm -rf $HOME` and reaches the rm rules in argument position, instead of
// dying as one unresolvable string (which used to mean the whole command was
// allowed outright; found researching the 2026-07 GPT-5.6 Codex
// home-directory deletions).
//
// The second return value reports a `-c` script operand that cannot be
// recovered even as source text (it embeds command substitution or a
// runtime-only expansion) — the caller surfaces that as
// DynamicCommandPlaceholder. Deliberately not reported for eval: an
// unresolvable eval argument is dominated by the `eval "$(ssh-agent -s)"` /
// `eval "$(direnv hook bash)"` class of long-established, ubiquitous shell
// idioms, and flagging every one of those is exactly the false-positive
// profile docs/threat-model.md says gets a tool like this uninstalled. That
// asymmetry (its cost: `eval "$(echo 'rm -rf ~')"` stays invisible) is a
// disclosed gap in docs/threat-model.md §3, unchanged from before.
//
// Before this existed, cli/shell re-parsed only heredoc bodies, so wrapping
// any command in `sh -c '...'` — the single most obvious way to hide one —
// presented Facts.Command as "sh" with the whole payload as one inert string
// argument, and every rule in core/policy silently no-opped. Found by an
// adversarial review of the 2026-07 agent-asset expansion.
func embeddedShellScripts(words []string, nodes []*syntax.Word) ([]string, bool) {
	if len(words) < 2 || len(nodes) != len(words) {
		return nil, false
	}
	if words[0] == "eval" {
		// eval concatenates its arguments with a space and executes the
		// result. Each argument resolves to its value if static, else to its
		// parameter-expansion source text; if any argument is unknowable even
		// as source, the whole script is unknowable and nothing is
		// reinterpreted (the command still reaches the rules as an ordinary
		// "eval" call — see the doc comment for why this isn't flagged).
		parts := make([]string, 0, len(words)-1)
		for i, a := range words[1:] {
			if a == "" {
				src, ok := scriptWordValue(nodes[1:][i])
				if !ok {
					return nil, false
				}
				a = src
			}
			parts = append(parts, a)
		}
		return []string{strings.Join(parts, " ")}, false
	}
	if !shellReinterpretCommands[words[0]] {
		return nil, false
	}
	for i, a := range words[1:] {
		if !isDashCFlag(a) {
			continue
		}
		script := words[1:][i+1:]
		if len(script) == 0 {
			return nil, false
		}
		// Only the first operand is the script; anything after it becomes
		// $0/$1... for the script, not more code.
		if script[0] != "" {
			return []string{script[0]}, false
		}
		src, ok := scriptWordValue(nodes[1:][i+1])
		if !ok {
			return nil, true
		}
		return []string{src}, false
	}
	return nil, false
}

// isDashCFlag reports whether a word is an interpreter's -c flag, either on
// its own or inside a short-option cluster ("-lc", "-ec"). A long option
// ("--norc") never carries -c's meaning.
func isDashCFlag(a string) bool {
	if len(a) < 2 || a[0] != '-' || a[1] == '-' {
		return false
	}
	return strings.ContainsRune(a[1:], 'c')
}

// walkWordSubstitutions descends into a word looking for embedded command or
// process substitution — no matter where the word appears (argument,
// assignment value, redirect target) — and walks the embedded statements as
// if they were their own top-level script.
func walkWordSubstitutions(w *syntax.Word, raw string, out *[]policy.Facts, depth int) {
	if w == nil {
		return
	}
	for _, part := range w.Parts {
		walkPartSubstitutions(part, raw, out, depth)
	}
}

func walkPartSubstitutions(part syntax.WordPart, raw string, out *[]policy.Facts, depth int) {
	switch p := part.(type) {
	case *syntax.CmdSubst:
		walkStmts(p.Stmts, raw, out, depth)
	case *syntax.ProcSubst:
		walkStmts(p.Stmts, raw, out, depth)
	case *syntax.DblQuoted:
		for _, inner := range p.Parts {
			walkPartSubstitutions(inner, raw, out, depth)
		}
	case *syntax.ParamExp:
		// Every operand of a parameter expansion evaluates at expansion
		// time, so a substitution hidden in any of them runs exactly like a
		// bare $(cmd): the default/alternate word (${x:-$(cmd)}), the
		// replace operands (${x/$(cmd)/y}), the slice offsets
		// (${x:$(cmd):n}), and the subscript (${arr[$(cmd)]}).
		walkArithmExpr(p.Index, raw, out, depth)
		if p.Slice != nil {
			walkArithmExpr(p.Slice.Offset, raw, out, depth)
			walkArithmExpr(p.Slice.Length, raw, out, depth)
		}
		if p.Repl != nil {
			walkWordSubstitutions(p.Repl.Orig, raw, out, depth)
			walkWordSubstitutions(p.Repl.With, raw, out, depth)
		}
		if p.Exp != nil {
			walkWordSubstitutions(p.Exp.Word, raw, out, depth)
		}
	case *syntax.ArithmExp:
		// $(( $(cmd) )) as a word part — distinct from the "(( ))"
		// arithmetic *command* walkCmd handles; both embed full words.
		walkArithmExpr(p.X, raw, out, depth)
	}
}

func walkCmd(cmd syntax.Command, raw string, out *[]policy.Facts, depth int) {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		// Command/process substitution executes at word-evaluation time
		// regardless of how its output is used — a destructive command
		// hidden in "echo $(rm -rf ~)" or "x=$(rm -rf ~)" runs whether or
		// not "echo"/"x" ever consumes the result. See
		// features/dangerous_command.feature, "command substitution used as
		// an argument, not the command name".
		for _, a := range c.Assigns {
			walkAssign(a, raw, out, depth)
		}
		for _, a := range c.Args {
			walkWordSubstitutions(a, raw, out, depth)
		}
		if len(c.Args) == 0 {
			return
		}
		resolved := callWords(c.Args)
		words := unwrapCommandPrefixes(resolved)
		// unwrapCommandPrefixes only ever strips words from the front, so the
		// unwrapped slice is a suffix of the input and the original AST word
		// nodes line up with it at the same tail offset.
		nodes := c.Args[len(resolved)-len(words):]
		// `sh -c "..."` / `eval "..."` execute their argument as shell code.
		// Walk it as its own script so the ordinary rules see the real
		// command, not one opaque string.
		scripts, dynamic := embeddedShellScripts(words, nodes)
		for _, script := range scripts {
			reinterpretScript(script, raw, out, depth)
		}
		if dynamic {
			// The interpreter will definitely execute its script operand as
			// shell code, and that operand cannot be resolved even to source
			// text (it embeds command substitution or a runtime-only
			// expansion) — the same "about to run code no rule can see" shape
			// DynamicCommandPlaceholder exists for. `bash -c "$(curl ...)"`
			// is the pipe-less twin of curl|sh, and was allowed outright
			// before this. Never assumed safe merely because it can't be
			// proven dangerous.
			*out = append(*out, policy.Facts{Raw: raw, Command: policy.DynamicCommandPlaceholder})
		}
		if f, ok := factsFromWords(words, raw); ok {
			*out = append(*out, f)
		}
	case *syntax.BinaryCmd:
		if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
			// The pipeline as a whole, for the pipeline-shape rules
			// (curl|sh, base64|sh, secret exfiltration).
			if f, ok := factsFromPipeline(c, raw); ok {
				*out = append(*out, f)
			}
			// ...and every stage on its own. A pipeline's Facts carries only
			// the stage *names* (PipelineCmds), never any stage's arguments,
			// so without this every argument-inspecting rule was bypassed by
			// appending a harmless pipe: `rm -rf ~/ | cat` was allowed
			// outright. Found by an adversarial review of the 2026-07
			// agent-asset expansion.
			walkPipelineStages(c, raw, out, depth)
			return
		}
		// && / || : each side may still contain its own destructive call.
		walkStmt(c.X, raw, out, depth)
		walkStmt(c.Y, raw, out, depth)
	case *syntax.Block:
		walkStmts(c.Stmts, raw, out, depth)
	case *syntax.Subshell:
		walkStmts(c.Stmts, raw, out, depth)
	case *syntax.IfClause:
		for cur := c; cur != nil; cur = cur.Else {
			walkStmts(cur.Cond, raw, out, depth)
			walkStmts(cur.Then, raw, out, depth)
		}
	case *syntax.WhileClause:
		walkStmts(c.Cond, raw, out, depth)
		walkStmts(c.Do, raw, out, depth)
	case *syntax.ForClause:
		walkLoopHeader(c.Loop, raw, out, depth)
		walkStmts(c.Do, raw, out, depth)
	case *syntax.FuncDecl:
		if c.Body != nil {
			walkStmt(c.Body, raw, out, depth)
		}
	case *syntax.TimeClause:
		// "time rm -rf ~/" — time is a reserved word, not a command word, so
		// mvdan/sh gives it its own node rather than a CallExpr whose first
		// argument is "time". Without this case the timed statement was never
		// walked at all and every rule silently no-opped.
		walkStmt(c.Stmt, raw, out, depth)
	case *syntax.CoprocClause:
		// "coproc $(rm -rf ~/) { sleep 1; }" — bash evaluates the optional
		// coprocess name's substitution before it ever checks whether the
		// result is a valid identifier, so the command runs even though the
		// coproc itself then fails to start. Confirmed against real bash,
		// not just mvdan/sh's parse tree.
		if c.Name != nil {
			walkWordSubstitutions(c.Name, raw, out, depth)
		}
		walkStmt(c.Stmt, raw, out, depth)
	case *syntax.CaseClause:
		walkWordSubstitutions(c.Word, raw, out, depth)
		for _, item := range c.Items {
			for _, p := range item.Patterns {
				walkWordSubstitutions(p, raw, out, depth)
			}
			walkStmts(item.Stmts, raw, out, depth)
		}
	case *syntax.DeclClause:
		// "declare v=$(rm -rf ~/)" — the substitution executes regardless of
		// what the declared variable is ever used for.
		for _, a := range c.Args {
			walkAssign(a, raw, out, depth)
		}
	case *syntax.TestClause:
		// "[[ -n $(rm -rf ~/) ]]" — same reasoning as DeclClause.
		walkTestExpr(c.X, raw, out, depth)
	case *syntax.ArithmCmd:
		// "(( $(rm -rf ~/) ))" — the substitution executes to produce the
		// arithmetic operand regardless of whether the result is truthy.
		walkArithmExpr(c.X, raw, out, depth)
	case *syntax.LetClause:
		// "let \"x=$(rm -rf ~/)\"" — same reasoning as ArithmCmd; let just
		// takes a list of arithmetic expressions instead of one.
		for _, e := range c.Exprs {
			walkArithmExpr(e, raw, out, depth)
		}
	}
}

// walkAssign descends every word- or arithmetic-bearing part of a variable
// assignment: the plain value ("x=$(rm -rf ~/)"), an array index
// ("x[$(rm -rf ~/)]=1"), and an array literal's own elements and each
// element's own index ("x=($(rm -rf ~/) safe)", "x=([$(rm -rf ~/)]=safe)").
// Each executes its substitution at assignment time regardless of what the
// assigned variable is ever used for — found alongside the ForClause/
// ArithmCmd/LetClause gaps by the same review: Assign.Index and Assign.Array
// were reachable from both *syntax.CallExpr and *syntax.DeclClause but never
// visited by either.
func walkAssign(a *syntax.Assign, raw string, out *[]policy.Facts, depth int) {
	if a.Value != nil {
		walkWordSubstitutions(a.Value, raw, out, depth)
	}
	walkArithmExpr(a.Index, raw, out, depth)
	if a.Array != nil {
		for _, elem := range a.Array.Elems {
			walkArithmExpr(elem.Index, raw, out, depth)
			if elem.Value != nil {
				walkWordSubstitutions(elem.Value, raw, out, depth)
			}
		}
	}
}

// walkLoopHeader descends a for-loop's header, which mvdan/sh models
// separately from the loop body (ForClause.Do): either a word list
// ("for f in $(rm -rf ~/x)") or a C-style arithmetic header
// ("for ((i=0; i<$(rm -rf ~/x); i++))"). Both evaluate their substitutions at
// loop-setup time whether or not the body ever runs, and neither was ever
// visited by the walker before this — a destructive command hidden in either
// position ran with no rule ever seeing it.
func walkLoopHeader(loop syntax.Loop, raw string, out *[]policy.Facts, depth int) {
	switch l := loop.(type) {
	case *syntax.WordIter:
		for _, item := range l.Items {
			walkWordSubstitutions(item, raw, out, depth)
		}
	case *syntax.CStyleLoop:
		walkArithmExpr(l.Init, raw, out, depth)
		walkArithmExpr(l.Cond, raw, out, depth)
		walkArithmExpr(l.Post, raw, out, depth)
	}
}

// walkArithmExpr descends an arithmetic expression tree looking for the
// words that may carry command/process substitution. An ArithmExpr is
// always one of *BinaryArithm/*UnaryArithm/*ParenArithm/*FlagsArithm
// wrapping further ArithmExpr nodes, bottoming out at a *Word leaf — see
// mvdan.cc/sh/v3/syntax's ArithmExpr doc comment. A nil expression (an
// omitted C-style loop clause, e.g. "for ((;;))") matches no case below and
// is a no-op.
func walkArithmExpr(x syntax.ArithmExpr, raw string, out *[]policy.Facts, depth int) {
	switch a := x.(type) {
	case *syntax.Word:
		walkWordSubstitutions(a, raw, out, depth)
	case *syntax.BinaryArithm:
		walkArithmExpr(a.X, raw, out, depth)
		walkArithmExpr(a.Y, raw, out, depth)
	case *syntax.UnaryArithm:
		walkArithmExpr(a.X, raw, out, depth)
	case *syntax.ParenArithm:
		walkArithmExpr(a.X, raw, out, depth)
	case *syntax.FlagsArithm:
		walkArithmExpr(a.X, raw, out, depth)
	}
}

// walkTestExpr descends a "[[ ... ]]" expression tree looking for the words
// that may carry command substitution.
func walkTestExpr(x syntax.TestExpr, raw string, out *[]policy.Facts, depth int) {
	switch t := x.(type) {
	case *syntax.Word:
		walkWordSubstitutions(t, raw, out, depth)
	case *syntax.UnaryTest:
		walkTestExpr(t.X, raw, out, depth)
	case *syntax.BinaryTest:
		walkTestExpr(t.X, raw, out, depth)
		walkTestExpr(t.Y, raw, out, depth)
	case *syntax.ParenTest:
		walkTestExpr(t.X, raw, out, depth)
	}
}

// walkPipelineStages walks each stage of a pipeline as its own statement.
// mvdan/sh nests "a | b | c" as BinaryCmd(BinaryCmd(a, b), c), so the nested
// pipe nodes are flattened here rather than re-entering walkCmd — that would
// emit a redundant Facts value for every sub-pipeline prefix.
func walkPipelineStages(c *syntax.BinaryCmd, raw string, out *[]policy.Facts, depth int) {
	for _, side := range []*syntax.Stmt{c.X, c.Y} {
		if side == nil || side.Cmd == nil {
			continue
		}
		if inner, ok := side.Cmd.(*syntax.BinaryCmd); ok && (inner.Op == syntax.Pipe || inner.Op == syntax.PipeAll) {
			collectRedirectWrites(side, raw, out)
			collectRedirectSubstitutions(side, raw, out, depth)
			walkPipelineStages(inner, raw, out, depth)
			continue
		}
		walkStmt(side, raw, out, depth)
	}
}
