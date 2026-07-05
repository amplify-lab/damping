package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	hookadapter "github.com/amplify-lab/damping/cli/adapter/hook"
	"github.com/amplify-lab/damping/cli/paths"
	"github.com/amplify-lab/damping/cli/ui"
	"github.com/amplify-lab/damping/core/audit"
	"github.com/amplify-lab/damping/core/decision"
	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

// claudeHookInput is the subset of Claude Code's PreToolUse stdin JSON that
// damping needs — see docs/cli-reference.md §11 for the verified contract.
type claudeHookInput struct {
	SessionID string `json:"session_id"`
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
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

// runHook implements the Claude Code PreToolUse contract: stdin/stdout are
// reserved for the JSON protocol with Claude Code itself (see
// docs/cli-reference.md §11), so the interactive confirmation prompt for a
// Prompt-tier decision must NOT use them — it talks to the controlling
// terminal (/dev/tty) instead via openTTYPrompter. By the time this function
// responds to Claude Code, the decision is always fully resolved to a plain
// allow/deny — Damping never asks Claude Code to show its own generic "ask"
// UI, because that would bypass Damping's own branded prompt (see
// docs/cli-reference.md §12) entirely.
func runHook(cmd *cobra.Command, hookEvent string) error {
	if hookEvent != "pretooluse" {
		return fmt.Errorf("unsupported hook event %q", hookEvent)
	}

	var in claudeHookInput
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

	if in.ToolName != "Bash" {
		return nil // not a shell command; nothing for Damping's V1 CLI adapter to judge
	}

	if disabled, _ := IsDisabled(); disabled {
		return nil // damping off — see docs/cli-reference.md §6
	}

	policyPath, err := resolvePolicyPath()
	if err != nil {
		logDegraded(cmd, writer, hasAuditSink, in.SessionID, "claude-code", "resolving policy path: "+err.Error())
		return nil
	}
	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		logDegraded(cmd, writer, hasAuditSink, in.SessionID, "claude-code", "loading policy: "+err.Error())
		return nil
	}
	engine := policy.New(cfg)

	d, err := hookadapter.EvaluateCommand(in.ToolInput.Command, engine)
	if err != nil {
		logDegraded(cmd, writer, hasAuditSink, in.SessionID, "claude-code", "analyzing command: "+err.Error())
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
			resolution := prompter.Confirm(in.ToolInput.Command, d)
			d.Resolve(resolution.Verdict)
			closeTTY()

			if resolution.Persist {
				if err := policy.AppendAlwaysPattern(policyPath, resolution.Verdict, in.ToolInput.Command); err != nil {
					logDegraded(cmd, writer, hasAuditSink, in.SessionID, "claude-code", "persisting always-"+string(resolution.Verdict)+" pattern: "+err.Error())
				}
			}
		}
	}

	if hasAuditSink {
		ev := hookadapter.BuildActionEvent(event.NewID(), in.SessionID, "claude-code", in.ToolInput.Command, d)
		if err := writer.Append(ev); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "damping: failed to write audit record: %v\n", err)
		}
	}

	if d.Outcome() == decision.Deny {
		fmt.Fprintln(cmd.ErrOrStderr(), d.Reason)
		// Exit code 2 is the only reliable blocking path Claude Code
		// recognizes — see docs/cli-reference.md §11.
		return &ExitCodeError{Code: 2}
	}
	// Allow (directly, or resolved from a prompt): exit 0, Claude Code
	// proceeds through its normal permission flow.
	return nil
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
