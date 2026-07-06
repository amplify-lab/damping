package cmd

import (
	"encoding/json"
	"fmt"

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

	var actor, sessionID, rawCommand string
	switch in.HookEventName {
	case "PreToolUse":
		if in.ToolName != "Bash" {
			return nil // not a shell command; nothing for Damping's V1 CLI adapter to judge
		}
		actor = "claude-code"
		if in.TurnID != "" || in.ToolUseID != "" {
			actor = "codex"
		}
		sessionID, rawCommand = in.SessionID, in.ToolInput.Command
	case "beforeShellExecution":
		actor, sessionID, rawCommand = "cursor", in.ConversationID, in.Command
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

	d, err := evaluateCommandRecovering(rawCommand, engine)
	if err != nil {
		logDegraded(cmd, writer, hasAuditSink, sessionID, actor, "analyzing command: "+err.Error())
		return nil
	}

	if d.Verdict == decision.Prompt {
		prompter, closeTTY, err := newTTYPrompter()
		if err != nil {
			// No controlling terminal available (e.g. a background/CI
			// execution context) — a Prompt-tier decision that can't be
			// asked defaults to Deny, the same conservative fallback
			// ui.TTYPrompter itself uses when stdin closes mid-prompt.
			d.Resolve(decision.Deny)
			d.Reason = "no controlling terminal available to ask; denied by default: " + d.Reason
		} else {
			resolution := prompter.Confirm(rawCommand, d)
			d.Resolve(resolution.Verdict)
			closeTTY()

			if resolution.Persist {
				if err := policy.AppendAlwaysPattern(policyPath, resolution.Verdict, rawCommand); err != nil {
					logDegraded(cmd, writer, hasAuditSink, sessionID, actor, "persisting always-"+string(resolution.Verdict)+" pattern: "+err.Error())
				}
			}
		}
	}

	if hasAuditSink {
		ev := hookadapter.BuildActionEvent(event.NewID(), sessionID, actor, rawCommand, d)
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
