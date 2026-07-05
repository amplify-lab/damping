// Package ui implements the interactive TTY confirmation prompt shown for
// Prompt-tier decisions. See docs/cli-reference.md §12 for the exact copy
// this is meant to render.
package ui

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/amplify-lab/damping/core/decision"
)

// Resolution is a human's answer to a Prompt-tier decision: the immediate
// verdict, plus whether they asked for it to be remembered ("always
// allow"/"always deny") rather than applying just this once.
type Resolution struct {
	Verdict decision.Verdict
	Persist bool
}

// Prompter resolves a Prompt-tier decision by asking a human. The real
// terminal implementation is TTYPrompter; tests inject a scripted fake so
// the hook/policy-test code paths are exercised without a real TTY.
type Prompter interface {
	Confirm(raw string, d decision.Decision) Resolution
	// Notify tells the human something outside the allow/deny question
	// itself — e.g. cli/adapter/mcp uses this to say a requested "always"
	// choice wasn't actually persisted, since MCP tool-call persistence
	// isn't implemented in V1 (see wrap.go's resolvePrompt). Silently
	// discarding an unsupported "always" choice would contradict what the
	// prompt itself just told the user it would do.
	Notify(msg string)
}

// TTYPrompter reads a single-character response from an io.Reader and
// writes the prompt to an io.Writer — see docs/cli-reference.md §12 for the
// exact copy. Input is case-sensitive: lowercase is "just this once",
// uppercase is "always" (persisted by the caller into the policy file's
// always_allow/always_deny list — see cli/cmd/hook.go and
// core/policy.AppendAlwaysPattern).
type TTYPrompter struct {
	In  io.Reader
	Out io.Writer
}

func (p TTYPrompter) Confirm(raw string, d decision.Decision) Resolution {
	fmt.Fprintf(p.Out, "\n⚠  Damping intercepted a destructive command\n\n")
	fmt.Fprintf(p.Out, "  Command: %s\n", raw)
	fmt.Fprintf(p.Out, "  Rule:    %s\n", d.PolicyID)
	fmt.Fprintf(p.Out, "  Reason:  %s\n\n", d.Reason)
	fmt.Fprintf(p.Out, "  [a] Allow once   [A] Always allow this exact command\n")
	fmt.Fprintf(p.Out, "  [d] Deny once    [D] Always deny this exact command\n")

	scanner := bufio.NewScanner(p.In)
	for {
		fmt.Fprint(p.Out, "> ")
		if !scanner.Scan() {
			// Input closed unexpectedly (e.g. non-interactive session) —
			// deny by default rather than silently allowing a destructive
			// command through on an EOF, per "prefer under-blocking to
			// over-annoying" being about false positives, not about safety
			// under ambiguous I/O state.
			return Resolution{Verdict: decision.Deny}
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "a":
			return Resolution{Verdict: decision.Allow}
		case "A":
			return Resolution{Verdict: decision.Allow, Persist: true}
		case "d":
			return Resolution{Verdict: decision.Deny}
		case "D":
			return Resolution{Verdict: decision.Deny, Persist: true}
		default:
			fmt.Fprintln(p.Out, "please enter 'a', 'A', 'd', or 'D'")
		}
	}
}

func (p TTYPrompter) Notify(msg string) {
	fmt.Fprintln(p.Out, msg)
}
