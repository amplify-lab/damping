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

// Prompter resolves a Prompt-tier decision by asking a human. The real
// terminal implementation is TTYPrompter; tests inject a scripted fake so
// the hook/policy-test code paths are exercised without a real TTY.
type Prompter interface {
	Confirm(raw string, d decision.Decision) decision.Verdict
}

// TTYPrompter reads a single-character response from an io.Reader and
// writes the prompt to an io.Writer. V1 supports "allow once" / "deny once"
// ([a]/[d]); the "always allow/deny" pattern persistence described in
// docs/cli-reference.md §12 ([A]/[D]) is tracked as a near-term follow-up —
// it requires writing back into the policy YAML file, which this minimal
// prompter deliberately does not attempt yet, rather than faking success.
type TTYPrompter struct {
	In  io.Reader
	Out io.Writer
}

func (p TTYPrompter) Confirm(raw string, d decision.Decision) decision.Verdict {
	fmt.Fprintf(p.Out, "\n⚠  Damping intercepted a destructive command\n\n")
	fmt.Fprintf(p.Out, "  Command: %s\n", raw)
	fmt.Fprintf(p.Out, "  Rule:    %s\n", d.PolicyID)
	fmt.Fprintf(p.Out, "  Reason:  %s\n\n", d.Reason)
	fmt.Fprintf(p.Out, "  [a] Allow once   [d] Deny once\n")

	scanner := bufio.NewScanner(p.In)
	for {
		fmt.Fprint(p.Out, "> ")
		if !scanner.Scan() {
			// Input closed unexpectedly (e.g. non-interactive session) —
			// deny by default rather than silently allowing a destructive
			// command through on an EOF, per "prefer under-blocking to
			// over-annoying" being about false positives, not about safety
			// under ambiguous I/O state.
			return decision.Deny
		}
		switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
		case "a":
			return decision.Allow
		case "d":
			return decision.Deny
		default:
			fmt.Fprintln(p.Out, "please enter 'a' or 'd'")
		}
	}
}
