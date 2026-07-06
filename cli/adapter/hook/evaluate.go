// Package hook implements the CLI-side half of Claude Code / Cursor
// PreToolUse-style integration: turning a raw shell command into a policy
// decision, and turning a hook invocation's input into an ActionEvent. See
// docs/cli-reference.md §11 for the exact external wire contract this
// supports, and docs/architecture.md §6 for the exit-code/JSON rules.
package hook

import (
	"github.com/amplify-lab/damping/cli/shell"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

var verdictRank = map[decision.Verdict]int{
	decision.Allow:  0,
	decision.Prompt: 1,
	decision.Deny:   2,
}

// EvaluateCommand parses raw shell text and returns the worst-case Decision
// across every command/pipeline it contains — a script with one dangerous
// line anywhere is treated as dangerous overall. This is the shared
// evaluation path used by both `damping policy test` (dry run) and the real
// `damping hook pretooluse` entrypoint.
func EvaluateCommand(raw string, engine policy.Evaluator) (decision.Decision, error) {
	facts, err := shell.Analyze(raw)
	if err != nil {
		return decision.Decision{}, err
	}
	worst := decision.Decision{Verdict: decision.Allow}
	for _, f := range facts {
		d := engine.Evaluate(f)
		if verdictRank[d.Verdict] > verdictRank[worst.Verdict] {
			worst = d
		}
	}
	return worst, nil
}

// BuildActionEvent normalizes a hook invocation plus its final decision into
// the transport-agnostic ActionEvent. Called once, after any TTY resolution
// of a Prompt decision has already happened, so exactly one coherent record
// is ever written for a given intercepted action — see
// features/audit_log.feature.
func BuildActionEvent(eventID string, sessionID, actor, raw string, d decision.Decision) event.ActionEvent {
	return event.New(eventID, sessionID, actor, event.ChannelCLI, event.ActionShellExec, raw, raw, d)
}

// BuildConfigWriteActionEvent is BuildActionEvent's counterpart for a
// Write/Edit/MultiEdit tool call (event.ActionConfigWrite — see the 2026-07
// non-Bash attack-surface expansion, cli/cmd/hook.go). Takes target
// separately from raw, unlike BuildActionEvent: for a shell command the
// command text itself is both the meaningful audit record and the
// evaluation key, but for a file write the target path is the concise,
// human-meaningful identifier while raw carries the (potentially large)
// full written content — see docs/threat-model.md and
// cli/adapter/hook/configwrite.go's FactsFromToolWrite doc comment.
func BuildConfigWriteActionEvent(eventID string, sessionID, actor, target, raw string, d decision.Decision) event.ActionEvent {
	return event.New(eventID, sessionID, actor, event.ChannelCLI, event.ActionConfigWrite, target, raw, d)
}
