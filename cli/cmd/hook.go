package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	hookadapter "github.com/amplify-lab/damping/cli/adapter/hook"
	"github.com/amplify-lab/damping/cli/enforcement"
	"github.com/amplify-lab/damping/cli/paths"
	"github.com/amplify-lab/damping/cli/ui"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

// hookInput is the union of every supported agent's `damping hook
// pretooluse` stdin shape — see docs/cli-reference.md §11 for the verified
// contract. Claude Code, Cursor, and Codex are all wired to invoke the
// exact same command (see cli/adapter/agent's shared HookCommand), so the
// payload's own shape is the only signal that distinguishes them.
// HookEventName is the primary discriminator ("beforeShellExecution" only
// ever means Cursor), but it is NOT sufficient on its own anymore: Codex's
// PreToolUse hook deliberately sends the identical hook_event_name value
// Claude Code uses (verified against developers.openai.com/codex/hooks —
// OpenAI built Codex's hook contract to be Claude-Code-hook-script
// compatible, this is why). The two are told apart by TurnID/ToolUseID:
// Codex's real payload includes them, Claude Code's does not (Claude Code
// sends a PromptID instead) — see the "PreToolUse" case below.
//
// A review found the previous version of this struct only ever decoded
// Claude Code's shape — a real Cursor beforeShellExecution payload has no
// tool_name at all, so it silently decoded to "" and hit the `!= "Bash"`
// early-return below, meaning every Cursor-intercepted command was
// evaluated by nothing and always allowed, despite `damping doctor`/
// `status` reporting the Cursor hook as actively registered.
type hookInput struct {
	HookEventName string `json:"hook_event_name"` // "PreToolUse" (Claude Code, Codex) or "beforeShellExecution" (Cursor)

	// Claude Code / Codex (PreToolUse) shape — shared, since both send it.
	SessionID string `json:"session_id"`
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`

		// Write/Edit/MultiEdit fields — the 2026-07 non-Bash attack-surface
		// expansion (see core/policy/rules_configwrite.go). Claude Code only:
		// Cursor has no pre-write hook and Codex's PreToolUse never fires for
		// these tool names — see docs/cli-reference.md §11.
		FilePath  string `json:"file_path"`
		Content   string `json:"content"`    // Write
		OldString string `json:"old_string"` // Edit
		NewString string `json:"new_string"` // Edit
		Edits     []struct {
			OldString string `json:"old_string"`
			NewString string `json:"new_string"`
		} `json:"edits"` // MultiEdit
	} `json:"tool_input"`
	// TurnID/ToolUseID: present in Codex's payload, absent in Claude
	// Code's — the discriminator between the two (see doc comment above).
	TurnID    string `json:"turn_id"`
	ToolUseID string `json:"tool_use_id"`

	// Cursor (beforeShellExecution) shape.
	ConversationID string `json:"conversation_id"`
	Command        string `json:"command"`
}

func newHookCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "hook <event>",
		Short:  "Internal entrypoint invoked by agent hook configs (not for direct interactive use)",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runHook(cmd, args[0])
		},
	}
}

// runHook implements both Claude Code's PreToolUse and Cursor's
// beforeShellExecution contracts (see docs/cli-reference.md §11) — the two
// agents invoke the exact same `damping hook pretooluse` command (see
// hookInput's doc comment for how the payload shape distinguishes them).
// Both agents' stdin/stdout are reserved for their own JSON protocol, so
// the interactive confirmation prompt for a Prompt-tier decision must NOT
// use them — it talks to the controlling terminal (/dev/tty) instead via
// openTTYPrompter. By the time this function responds, the decision is
// always fully resolved to a plain allow/deny — Damping never asks the
// agent to show its own generic "ask" UI, because that would bypass
// Damping's own branded prompt (see docs/cli-reference.md §12) entirely.
func runHook(cmd *cobra.Command, hookEvent string) error {
	if hookEvent != "pretooluse" {
		return fmt.Errorf("unsupported hook event %q", hookEvent)
	}

	var in hookInput
	decodeErr := json.NewDecoder(cmd.InOrStdin()).Decode(&in)
	writer, hasAuditSink := newAuditWriter()

	// Malformed stdin from the agent itself: fail open (Damping cannot force
	// a fail-closed outcome once the surrounding agent's own hook contract
	// takes over on anything but exit code 2 — see docs/threat-model.md §6)
	// but still leave a loud, logged trace of the degradation — logDegraded
	// falls back to stderr if the audit sink itself isn't available or the
	// write fails, so this is never a fully silent failure either way.
	if decodeErr != nil {
		logDegraded(cmd, writer, hasAuditSink, "unknown", "unknown", "malformed hook input: "+decodeErr.Error())
		return nil
	}

	// isConfigWrite selects the evaluation/display/audit path below: false
	// means the shell-AST path (auditRaw is a full command line, matched via
	// shell.Analyze), true means the Write/Edit/MultiEdit Facts-direct path
	// (auditRaw is FactsFromToolWrite's path+content text, auditTarget is
	// just the file path). displayText is always what the TTY Confirm
	// prompt and a deny's stderr line show a human — kept short for the
	// config-write path (see truncateForDisplay) since auditRaw there can be
	// an entire file's contents.
	var actor, sessionID, rawCommand, displayText, auditTarget string
	var facts policy.Facts
	var isConfigWrite bool
	switch in.HookEventName {
	case "PreToolUse":
		actor = "claude-code"
		if in.TurnID != "" || in.ToolUseID != "" {
			actor = "codex"
		}
		sessionID = in.SessionID

		switch in.ToolName {
		case "Bash":
			rawCommand = in.ToolInput.Command
			displayText = rawCommand
		case "Write":
			facts = hookadapter.FactsFromToolWrite("Write", hookadapter.ToolWriteInput{
				FilePath: in.ToolInput.FilePath,
				Content:  in.ToolInput.Content,
			})
			isConfigWrite = true
			auditTarget = facts.Target
			displayText = "Write " + in.ToolInput.FilePath + "\n" + truncateForDisplay(in.ToolInput.Content)
		case "Edit":
			facts = hookadapter.FactsFromToolWrite("Edit", hookadapter.ToolWriteInput{
				FilePath: in.ToolInput.FilePath,
				Edits:    []hookadapter.ToolEditOp{{OldString: in.ToolInput.OldString, NewString: in.ToolInput.NewString}},
			})
			isConfigWrite = true
			auditTarget = facts.Target
			displayText = "Edit " + in.ToolInput.FilePath + "\n" + truncateForDisplay(in.ToolInput.NewString)
		case "MultiEdit":
			edits := make([]hookadapter.ToolEditOp, 0, len(in.ToolInput.Edits))
			newStrings := make([]string, 0, len(in.ToolInput.Edits))
			for _, e := range in.ToolInput.Edits {
				edits = append(edits, hookadapter.ToolEditOp{OldString: e.OldString, NewString: e.NewString})
				newStrings = append(newStrings, e.NewString)
			}
			facts = hookadapter.FactsFromToolWrite("MultiEdit", hookadapter.ToolWriteInput{
				FilePath: in.ToolInput.FilePath,
				Edits:    edits,
			})
			isConfigWrite = true
			auditTarget = facts.Target
			displayText = "MultiEdit " + in.ToolInput.FilePath + "\n" + truncateForDisplay(strings.Join(newStrings, "\n"))
		default:
			return nil // not a tool call Damping's V1 CLI adapter judges (see hookInput's doc comment)
		}
	case "beforeShellExecution":
		actor, sessionID, rawCommand = "cursor", in.ConversationID, in.Command
		displayText = rawCommand
	default:
		// An unrecognized hook_event_name means a third agent (or a future,
		// unrecognized event from Claude Code/Cursor themselves) is calling
		// this hook — not "nothing to judge here." Treating it as a silent
		// no-op let the command run completely unchecked with zero trace,
		// quieter even than the malformed-JSON path above. Log it the same
		// way instead, so an unrecognized agent shows up in `damping doctor`
		// rather than vanishing.
		logDegraded(cmd, writer, hasAuditSink, "unknown", "unknown", fmt.Sprintf("unrecognized hook_event_name %q: no policy evaluation performed", in.HookEventName))
		return nil
	}
	if sessionID == "" {
		sessionID = "unknown"
	}

	if disabled, _ := enforcement.IsDisabled(); disabled {
		return nil // damping off — see docs/cli-reference.md §6
	}

	policyPath, err := resolvePolicyPath()
	if err != nil {
		logDegraded(cmd, writer, hasAuditSink, sessionID, actor, "resolving policy path: "+err.Error())
		return nil
	}
	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		logDegraded(cmd, writer, hasAuditSink, sessionID, actor, "loading policy: "+err.Error())
		return nil
	}
	engine, err := policy.NewEvaluator(cmd.Context(), cfg)
	if err != nil {
		logDegraded(cmd, writer, hasAuditSink, sessionID, actor, "constructing policy engine: "+err.Error())
		return nil
	}

	var d decision.Decision
	if isConfigWrite {
		d, err = evaluateFactsRecovering(facts, engine)
	} else {
		d, err = evaluateCommandRecovering(rawCommand, engine)
	}
	if err != nil {
		logDegraded(cmd, writer, hasAuditSink, sessionID, actor, "analyzing command: "+err.Error())
		return nil
	}

	// persistPattern is what an "always allow/deny" TTY choice below appends
	// to policy.yaml as an exact-match pattern (core/policy/patterns.go) —
	// the same text Evaluate actually matched against (Facts.Raw), so a
	// persisted pattern matches the same way the live decision did. For
	// Write, that's the file's full new content, not just its path — see
	// hookadapter.FactsFromToolWrite's doc comment on why Raw carries both.
	persistPattern := rawCommand
	if isConfigWrite {
		persistPattern = facts.Raw
	}

	if d.Verdict == decision.Prompt {
		prompter, closeTTY, err := newTTYPrompter()
		if err != nil {
			// No controlling terminal available (e.g. a background/CI
			// execution context) — resolve per cfg.NonInteractivePromptFallback
			// if the matched rule's risk tier has an entry, otherwise the
			// same conservative Deny default ui.TTYPrompter itself uses when
			// stdin closes mid-prompt.
			d = resolveNonInteractivePrompt(d, cfg)
		} else {
			resolution := prompter.Confirm(displayText, d)
			d.Resolve(resolution.Verdict)
			closeTTY()

			if resolution.Persist {
				if err := policy.AppendAlwaysPattern(policyPath, resolution.Verdict, persistPattern); err != nil {
					logDegraded(cmd, writer, hasAuditSink, sessionID, actor, "persisting always-"+string(resolution.Verdict)+" pattern: "+err.Error())
				}
			}
		}
	}

	if hasAuditSink {
		var ev event.ActionEvent
		if isConfigWrite {
			ev = hookadapter.BuildConfigWriteActionEvent(event.NewID(), sessionID, actor, auditTarget, facts.Raw, d)
		} else {
			ev = hookadapter.BuildActionEvent(event.NewID(), sessionID, actor, rawCommand, d)
		}
		if err := writer.Append(ev); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "damping: failed to write audit record: %v\n", err)
		}
	}

	if d.Outcome() == decision.Deny {
		fmt.Fprintln(cmd.ErrOrStderr(), d.Reason)
		// Exit code 2 is the reliable blocking path both agents recognize —
		// Cursor treats it the same as returning {"permission":"deny"}, so
		// there's no need for this hook to also emit that JSON body on
		// stdout — see docs/cli-reference.md §11.
		return &ExitCodeError{Code: 2}
	}
	// Allow (directly, or resolved from a prompt): exit 0, the agent
	// proceeds through its normal permission flow.
	return nil
}

// resolveNonInteractivePrompt resolves a Prompt-tier decision when no
// controlling terminal is available to ask a human. Config.
// NonInteractivePromptFallback lets an operator opt a risk tier into a
// concrete verdict for exactly this situation (e.g. "medium" -> allow, so a
// background agent's everyday-but-flagged command isn't blocked purely
// because nobody was there to answer a prompt) instead of the historical
// unconditional Deny, which treated every risk tier identically whenever a
// command happened to run unattended. A risk tier with no configured entry
// — including when NonInteractivePromptFallback itself is nil, the default
// — keeps that original conservative behavior.
func resolveNonInteractivePrompt(d decision.Decision, cfg policy.Config) decision.Decision {
	verdict := decision.Deny
	reason := "no controlling terminal available to ask; denied by default: " + d.Reason
	if v, ok := cfg.NonInteractivePromptFallback[event.RiskLevel(d.Risk)]; ok {
		verdict = v
		reason = fmt.Sprintf("no controlling terminal available to ask; resolved to %s per noninteractive_prompt_fallback for risk %q: %s", v, d.Risk, d.Reason)
	}
	d.Resolve(verdict)
	d.Reason = reason
	return d
}

// evaluateCommandRecovering wraps hookadapter.EvaluateCommand with a
// recover() so a genuine crash in shell.Analyze (adversarial input is, by
// design, the whole point of what this function parses — see
// cli/shell/fuzz_test.go) fails open with a logged degraded record, per
// docs/threat-model.md §6's explicit design, rather than crashing this
// entire subprocess.
//
// A review found this recover() didn't exist at all: an unhandled panic
// here used to exit the subprocess with Go's own default panic status
// (2), which happens to equal Damping's own hard-deny exit code today —
// so a crash accidentally failed closed instead of the documented fail-
// open-and-degraded behavior. That was never a deliberate design decision,
// just an unexamined coincidence of the Go runtime's default panic
// behavior — not something to depend on (a future Go version, or a panic
// on a different goroutine, isn't guaranteed to produce the same exit
// code), and it silently contradicted features/audit_log.feature's own
// "shell parser crashes -> fails open, logged degraded" scenario. Scoped
// to this one call site rather than cli/adapter/hook.EvaluateCommand
// itself, since `damping policy test` (an interactive, foreground command
// a human runs directly) should still show a real panic/stack trace for
// debugging, not have it silently swallowed the same way an unattended
// hook invocation should.
func evaluateCommandRecovering(raw string, engine policy.Evaluator) (d decision.Decision, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("shell.Analyze panicked: %v", r)
		}
	}()
	return hookadapter.EvaluateCommand(raw, engine)
}

// evaluateFactsRecovering is evaluateCommandRecovering's counterpart for the
// Write/Edit/MultiEdit Facts-direct path: engine.Evaluate itself runs
// regexes against a full file's contents (see
// core/policy/rules_configwrite.go), untrusted input in the same sense
// shell.Analyze's is, so it gets the same fail-open-and-degraded treatment
// on a panic rather than crashing this subprocess.
func evaluateFactsRecovering(f policy.Facts, engine policy.Evaluator) (d decision.Decision, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("policy.Evaluate panicked: %v", r)
		}
	}()
	return engine.Evaluate(f), nil
}

// truncateForDisplay bounds how much of a Write/Edit/MultiEdit's content
// reaches the terminal — ui.TTYPrompter.Confirm prints its argument
// verbatim on a single "Command: %s" line with no truncation of its own
// (unlike a shell command, file content can be arbitrarily large/multi-line
// and would otherwise blow out the confirmation prompt's layout). This only
// affects what a human sees at the prompt; policy matching and the audit
// log both still use the full, untruncated text (Facts.Raw).
func truncateForDisplay(s string) string {
	const maxLines = 12
	const maxChars = 800
	truncated := false
	if lines := strings.Split(s, "\n"); len(lines) > maxLines {
		s = strings.Join(lines[:maxLines], "\n")
		truncated = true
	}
	if len(s) > maxChars {
		s = s[:maxChars]
		truncated = true
	}
	if truncated {
		s += "\n... (truncated for display; full content evaluated and logged)"
	}
	return s
}

// newTTYPrompter is a package-level var (not a direct call to
// ui.OpenTTYPrompter) so tests can substitute a scripted fake reader
// instead of a real controlling terminal — see cmd_test.go's
// TestHook_PersistsAlwaysAllowPattern. cli/adapter/mcp uses
// ui.OpenTTYPrompter directly for the same reason (see docs/architecture.md
// §6/§7) — both adapters share one implementation now instead of each
// opening /dev/tty themselves.
var newTTYPrompter = ui.OpenTTYPrompter

func newAuditWriter() (*audit.Writer, bool) {
	p, err := paths.Audit()
	if err != nil {
		return nil, false
	}
	return audit.NewWriter(p), true
}

// logDegraded records an internal failure as loudly as possible: as a
// degraded audit event if a sink is available and the write succeeds,
// falling back to stderr otherwise. Found via code review: the previous
// version silently dropped the failure entirely whenever hasAuditSink was
// false or Append itself errored — exactly the "protection failed and
// nobody knows" failure mode docs/threat-model.md §6 says must never
// happen.
func logDegraded(cmd *cobra.Command, writer *audit.Writer, hasAuditSink bool, sessionID, actor, reason string) {
	if hasAuditSink {
		if err := writer.Append(degradedEvent(sessionID, actor, reason)); err == nil {
			return
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "damping: %s\n", reason)
}

func degradedEvent(sessionID, actor, reason string) event.ActionEvent {
	return hookadapter.BuildActionEvent(event.NewID(), sessionID, actor, "", decision.Decision{
		Verdict:  decision.Allow,
		Degraded: true,
		Reason:   reason,
	})
}
