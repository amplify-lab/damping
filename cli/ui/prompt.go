// Package ui implements the interactive TTY confirmation prompt shown for
// Prompt-tier decisions. See docs/cli-reference.md §12 for the exact copy
// this is meant to render.
package ui

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/amplify-lab/damping/cli/i18n"
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
	// itself — e.g. cli/adapter/mcp's resolvePrompt calls this when an
	// "always" choice was requested but couldn't actually be persisted (the
	// policy.AppendAlwaysPattern write itself failed, such as a disk-write
	// error), so the resolved verdict silently degrades to "this call only"
	// instead of contradicting what the prompt just told the user it would
	// do. MCP tool-call persistence is otherwise implemented the same way
	// the CLI hook's is: it writes to the policy file AND records into an
	// in-memory overlay so the rest of the same long-lived `mcp wrap`
	// session honors it immediately (see wrap.go's resolvePrompt and
	// always_overlay.go's doc comment for why that second step is needed
	// there but not for the CLI hook's one-shot subprocess).
	Notify(msg string)
}

// TTYPrompter reads a single-character response from an io.Reader and
// writes the prompt to an io.Writer — see docs/cli-reference.md §12 for the
// exact copy. Input is case-sensitive: lowercase is "just this once",
// uppercase is "always" (persisted by the caller into the policy file's
// always_allow/always_deny list — see cli/cmd/hook.go and
// core/policy.AppendAlwaysPattern).
//
// Lang controls which language the prompt's own labels ("Command:",
// "Rule:", "[a] Allow once"...) and the rule's Reason text render in — see
// cli/i18n. The zero value (Lang("")) is not a real language; every real
// construction site resolves a concrete i18n.Lang first (i18n.ResolveLang)
// and cli/i18n.Prompt/Reason both fall back to English for an unrecognized
// value regardless, so a zero-value TTYPrompter (as every existing test in
// this file already constructs) still renders correctly in English.
type TTYPrompter struct {
	In   io.Reader
	Out  io.Writer
	Lang i18n.Lang
}

func (p TTYPrompter) Confirm(raw string, d decision.Decision) Resolution {
	s := i18n.Prompt(p.Lang)
	fmt.Fprintf(p.Out, "\n%s\n\n", s.Intercepted)
	fmt.Fprintf(p.Out, "  %s%s\n", s.CommandLabel, raw)
	fmt.Fprintf(p.Out, "  %s%s\n", s.RuleLabel, d.PolicyID)
	fmt.Fprintf(p.Out, "  %s%s\n\n", s.ReasonLabel, i18n.Reason(d.PolicyID, p.Lang, d.Reason))
	fmt.Fprintf(p.Out, "  %s\n", s.AllowLine)
	fmt.Fprintf(p.Out, "  %s\n", s.DenyLine)

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
			fmt.Fprintln(p.Out, s.InvalidInput)
		}
	}
}

func (p TTYPrompter) Notify(msg string) {
	fmt.Fprintln(p.Out, msg)
}
