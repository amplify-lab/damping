package cmd

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	hookadapter "github.com/amplify-lab/damping/cli/adapter/hook"
	"github.com/amplify-lab/damping/cli/enforcement"
	"github.com/amplify-lab/damping/cli/i18n"
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
// compatible, this is why). The two are told apart by TurnID alone — see
// the "PreToolUse" case below.
//
// A real, live misattribution bug (found 2026-07-07 by directly capturing
// a genuine Claude Code session's actual hook stdin, not by re-reading
// docs) found ToolUseID is NOT a valid part of that discriminator: real
// Claude Code payloads DO send a non-empty tool_use_id (this struct's
// earlier doc comment, and the tests it was written against, wrongly
// assumed they never do) — every "codex" audit entry a real Claude-Code-
// only user ever saw was actually misattributed Claude Code traffic. Only
// TurnID (confirmed absent from that same real capture, and confirmed
// present in Codex's own documented PreToolUse contract) is exclusive to
// Codex.
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
	// ToolInput stays raw rather than a fixed struct: its shape is defined
	// per tool_name, and since the 2026-08 MCP-over-hook-channel expansion
	// that set is open-ended — an "mcp__<server>__<tool>" call carries
	// whatever arguments that server's schema declares, which Damping cannot
	// know in advance. The four built-in tool shapes are decoded on demand
	// into toolWriteInput below.
	ToolInput json.RawMessage `json:"tool_input"`
	// ToolAnnotations is Damping's own optional extension to the hook
	// contract — no agent sends it. An embedding host that already holds the
	// MCP server's tool list can attach the tool's MCP ToolAnnotations here,
	// which restores the annotation-driven mcp.destructive_tool_call rule on
	// this channel; see cli/adapter/hook.FactsFromMCPToolCall.
	ToolAnnotations *hookadapter.MCPToolAnnotations `json:"tool_annotations"`
	// TurnID: present in Codex's payload, absent in Claude Code's — the
	// discriminator between the two (see doc comment above). ToolUseID is
	// parsed but deliberately NOT used for discrimination — both agents
	// send it.
	TurnID    string `json:"turn_id"`
	ToolUseID string `json:"tool_use_id"`

	// Cursor (beforeShellExecution) shape.
	ConversationID string `json:"conversation_id"`
	Command        string `json:"command"`
}

// toolWriteInput is the tool_input shape for the built-in tools Damping
// judges directly — Bash's command line, and the Write/Edit/MultiEdit
// fields behind the 2026-07 non-Bash attack-surface expansion (see
// core/policy/rules_configwrite.go). Claude Code only for the write tools:
// Cursor has no pre-write hook and Codex's PreToolUse never fires for these
// tool names — see docs/cli-reference.md §11.
type toolWriteInput struct {
	Command string `json:"command"`

	FilePath  string `json:"file_path"`
	Content   string `json:"content"`    // Write
	OldString string `json:"old_string"` // Edit
	NewString string `json:"new_string"` // Edit
	Edits     []struct {
		OldString string `json:"old_string"`
		NewString string `json:"new_string"`
	} `json:"edits"` // MultiEdit
}

// hookOptions are the flags that only make sense for a host embedding
// Damping, never for the agent hook configs `damping init` writes — see
// docs/cli-reference.md §11.1. `damping init` deliberately registers the
// bare `damping hook pretooluse` for every agent, with neither flag.
type hookOptions struct {
	// hostJSON turns on the embedding-host response contract: a single JSON
	// object on stdout, and a Prompt-tier decision handed to the host's own
	// confirmation UI as "ask" instead of resolved at a terminal.
	hostJSON bool
	// actor overrides the audit trail's actor label. The payload-derived
	// actor ("claude-code"/"codex"/"cursor") describes the agent SDK, which
	// is exactly what a desktop host embedding that SDK is indistinguishable
	// from — so a host that shares an audit trail with the user's own CLI
	// agents needs to be able to say which one it is.
	actor string
}

// actorLabelPattern bounds what --actor can put into an audit record. The
// value is operator-supplied rather than agent-supplied, so this is not a
// trust boundary — but a newline or a megabyte of text in an actor field
// would corrupt the readability of a JSONL audit trail that other tools
// (damping log, the dashboard, Phase 5 compliance reports) parse, so it is
// rejected loudly at the edge instead.
var actorLabelPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func newHookCmd() *cobra.Command {
	var opts hookOptions
	c := &cobra.Command{
		Use:    "hook <event>",
		Short:  "Internal entrypoint invoked by agent hook configs (not for direct interactive use)",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.actor != "" && !actorLabelPattern.MatchString(opts.actor) {
				return fmt.Errorf("--actor %q: expected 1-64 characters of [a-zA-Z0-9._-] starting alphanumeric", opts.actor)
			}
			return runHook(cmd, args[0], opts)
		},
	}
	c.Flags().BoolVar(&opts.hostJSON, "hook-json", false,
		"Respond with the agent's hook-response JSON on stdout and defer prompt-tier decisions to the embedding host's own confirmation UI (for apps embedding an agent SDK; not for terminal agents)")
	c.Flags().StringVar(&opts.actor, "actor", "",
		"Label this caller in the audit trail instead of deriving the actor from the payload (e.g. the name of the app embedding Damping)")
	return c
}

// hookActionKind selects the evaluation/display/audit path for one
// intercepted action: a shell command line parsed through the shell AST, a
// Write/Edit/MultiEdit file write, or an MCP tool call arriving on the hook
// channel.
type hookActionKind int

const (
	actionShellCommand hookActionKind = iota
	actionConfigWrite
	actionMCPToolCall
)

// runHook implements Claude Code's / Codex's PreToolUse and Cursor's
// beforeShellExecution contracts (see docs/cli-reference.md §11) — all
// three agents invoke the exact same `damping hook pretooluse` command (see
// hookInput's doc comment for how the payload shape distinguishes them).
//
// Terminal agents' stdin/stdout are reserved for their own JSON protocol,
// so the interactive confirmation prompt for a Prompt-tier decision must
// NOT use them — it talks to the controlling terminal (/dev/tty) instead
// via openTTYPrompter. By the time this function responds, the decision is
// always fully resolved to a plain allow/deny — Damping never asks a
// terminal agent to show its own generic "ask" UI, because that would
// bypass Damping's own branded prompt (see docs/cli-reference.md §12)
// entirely, and because both agents' "ask" handling has documented
// fail-unsafe modes (see cli/adapter/hook/hostresponse.go's package notes).
//
// `--hook-json` is the one, explicitly opted-into exception: an application
// embedding an agent SDK has no terminal but does have a human and its own
// permission dialog, so there Damping writes the hook-response JSON and
// hands a Prompt-tier decision to the host to ask about.
func runHook(cmd *cobra.Command, hookEvent string, opts hookOptions) error {
	if hookEvent != "pretooluse" {
		return fmt.Errorf("unsupported hook event %q", hookEvent)
	}

	var in hookInput
	decodeErr := json.NewDecoder(cmd.InOrStdin()).Decode(&in)
	writer, hasAuditSink := newAuditWriter()
	h := &hookResponder{cmd: cmd, opts: opts, writer: writer, hasAuditSink: hasAuditSink}

	// Malformed stdin from the agent itself: fail open (Damping cannot force
	// a fail-closed outcome once the surrounding agent's own hook contract
	// takes over on anything but exit code 2 — see docs/threat-model.md §6)
	// but still leave a loud, logged trace of the degradation — logDegraded
	// falls back to stderr if the audit sink itself isn't available or the
	// write fails, so this is never a fully silent failure either way.
	if decodeErr != nil {
		return h.degraded("unknown", "unknown", "malformed hook input: "+decodeErr.Error())
	}

	// displayText is always what the TTY Confirm prompt and a deny's stderr
	// line show a human — kept short for the config-write and MCP paths (see
	// truncateForDisplay) since their auditRaw can be an entire file's
	// contents or a large argument object.
	var actor, sessionID, rawCommand, displayText, auditTarget string
	var facts policy.Facts
	kind := actionShellCommand
	switch in.HookEventName {
	case "PreToolUse":
		actor = "claude-code"
		if in.TurnID != "" {
			actor = "codex"
		}
		sessionID = in.SessionID

		toolInput, err := in.decodeToolInput()
		if err != nil {
			return h.degraded(orUnknown(in.SessionID), actor, "malformed tool_input for tool "+in.ToolName+": "+err.Error())
		}

		switch in.ToolName {
		case "Bash":
			rawCommand = toolInput.Command
			displayText = rawCommand
		case "Write":
			facts = hookadapter.FactsFromToolWrite("Write", hookadapter.ToolWriteInput{
				FilePath: toolInput.FilePath,
				Content:  toolInput.Content,
			})
			kind = actionConfigWrite
			auditTarget = facts.Target
			displayText = "Write " + toolInput.FilePath + "\n" + truncateForDisplay(toolInput.Content)
		case "Edit":
			facts = hookadapter.FactsFromToolWrite("Edit", hookadapter.ToolWriteInput{
				FilePath: toolInput.FilePath,
				Edits:    []hookadapter.ToolEditOp{{OldString: toolInput.OldString, NewString: toolInput.NewString}},
			})
			kind = actionConfigWrite
			auditTarget = facts.Target
			displayText = "Edit " + toolInput.FilePath + "\n" + truncateForDisplay(toolInput.NewString)
		case "MultiEdit":
			edits := make([]hookadapter.ToolEditOp, 0, len(toolInput.Edits))
			newStrings := make([]string, 0, len(toolInput.Edits))
			for _, e := range toolInput.Edits {
				edits = append(edits, hookadapter.ToolEditOp{OldString: e.OldString, NewString: e.NewString})
				newStrings = append(newStrings, e.NewString)
			}
			facts = hookadapter.FactsFromToolWrite("MultiEdit", hookadapter.ToolWriteInput{
				FilePath: toolInput.FilePath,
				Edits:    edits,
			})
			kind = actionConfigWrite
			auditTarget = facts.Target
			displayText = "MultiEdit " + toolInput.FilePath + "\n" + truncateForDisplay(strings.Join(newStrings, "\n"))
		default:
			// An MCP tool call ("mcp__<server>__<tool>") is the one remaining
			// tool_name family Damping judges here. `damping mcp wrap` only
			// reaches stdio servers it can proxy; for an HTTP/SSE server this
			// hook is the only interception point that exists at all — see
			// cli/adapter/hook.FactsFromMCPToolCall.
			if !hookadapter.IsMCPToolName(in.ToolName) {
				return h.noObjection("tool " + in.ToolName + " is not one Damping's CLI adapter judges")
			}
			facts = hookadapter.FactsFromMCPToolCall(in.ToolName, in.ToolInput, in.ToolAnnotations)
			kind = actionMCPToolCall
			auditTarget = facts.Target
			displayText = truncateForDisplay(facts.Raw)
		}
	case "beforeShellExecution":
		actor, sessionID, rawCommand = "cursor", in.ConversationID, in.Command
		displayText = rawCommand
		h.dialect = hookadapter.DialectCursor
	default:
		// An unrecognized hook_event_name means a third agent (or a future,
		// unrecognized event from Claude Code/Cursor themselves) is calling
		// this hook — not "nothing to judge here." Treating it as a silent
		// no-op let the command run completely unchecked with zero trace,
		// quieter even than the malformed-JSON path above. Log it the same
		// way instead, so an unrecognized agent shows up in `damping doctor`
		// rather than vanishing.
		return h.degraded("unknown", "unknown", fmt.Sprintf("unrecognized hook_event_name %q: no policy evaluation performed", in.HookEventName))
	}
	sessionID = orUnknown(sessionID)
	if opts.actor != "" {
		actor = opts.actor
	}

	if disabled, _ := enforcement.IsDisabled(); disabled {
		return h.noObjection("damping enforcement is off") // damping off — see docs/cli-reference.md §6
	}

	policyPath, err := resolvePolicyPath()
	if err != nil {
		return h.degraded(sessionID, actor, "resolving policy path: "+err.Error())
	}
	cfg, err := policy.LoadConfig(policyPath)
	if err != nil {
		return h.degraded(sessionID, actor, "loading policy: "+err.Error())
	}
	engine, err := policy.NewEvaluator(cmd.Context(), cfg)
	if err != nil {
		return h.degraded(sessionID, actor, "constructing policy engine: "+err.Error())
	}

	var d decision.Decision
	if kind == actionShellCommand {
		d, err = evaluateCommandRecovering(rawCommand, engine)
	} else {
		d, err = evaluateFactsRecovering(facts, engine)
	}
	if err != nil {
		return h.degraded(sessionID, actor, "analyzing command: "+err.Error())
	}

	// persistPattern is what an "always allow/deny" TTY choice below appends
	// to policy.yaml as an exact-match pattern (core/policy/patterns.go) —
	// the same text Evaluate actually matched against (Facts.Raw), so a
	// persisted pattern matches the same way the live decision did. For
	// Write, that's the file's full new content, not just its path — see
	// hookadapter.FactsFromToolWrite's doc comment on why Raw carries both.
	persistPattern := rawCommand
	if kind != actionShellCommand {
		persistPattern = facts.Raw
	}

	deferredToHost := false
	if d.Verdict == decision.Prompt {
		switch {
		case opts.hostJSON:
			// The host asked for this question, so it gets it — unless the
			// operator already answered it in advance for this risk tier, in
			// which case re-asking a human who was told they wouldn't be
			// asked is noise, not safety.
			if v, ok := cfg.NonInteractivePromptFallback[event.RiskLevel(d.Risk)]; ok {
				d.Resolve(v)
				d.Reason = fmt.Sprintf("resolved to %s per noninteractive_prompt_fallback for risk %q: %s", v, d.Risk, d.Reason)
			} else {
				deferredToHost = true
			}
		default:
			prompter, closeTTY, err := newTTYPrompter(i18n.ResolveLang(cfg.UILanguage))
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
	}

	eventID := event.NewID()
	if hasAuditSink {
		// The audit copy of the decision carries the deferral in its Reason:
		// the host-facing response keeps the matched rule's own clean text
		// for its dialog, while the permanent record has to say that nobody
		// here resolved this — the record stays a prompt verdict with no
		// resolved verdict, because Damping genuinely does not learn what the
		// human answered in the host's UI (closing that loop is the
		// audit-ingest follow-up in docs/cli-reference.md §11.1).
		auditDecision := d
		if deferredToHost {
			auditDecision.Reason = "deferred to the embedding host's own confirmation UI (--hook-json): " + d.Reason
		}
		ev := buildHookActionEvent(kind, eventID, sessionID, actor, auditTarget, rawCommand, facts.Raw, auditDecision)
		if err := writer.Append(ev); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "damping: failed to write audit record: %v\n", err)
		}
	}

	h.respond(hookadapter.HostResponseInput{
		Decision:   d,
		Deferred:   deferredToHost,
		EventID:    eventID,
		Channel:    hookChannel(kind),
		ActionType: hookActionType(kind),
		Target:     auditTarget,
	})

	if !deferredToHost && d.Outcome() == decision.Deny {
		fmt.Fprintln(cmd.ErrOrStderr(), d.Reason)
		// Exit code 2 is the reliable blocking path every agent recognizes —
		// Cursor treats it the same as returning {"permission":"deny"}, so
		// there's no need for this hook to also emit that JSON body on
		// stdout — see docs/cli-reference.md §11.
		return &ExitCodeError{Code: 2}
	}
	// Allow (directly, or resolved from a prompt), or deferred to the host:
	// exit 0, and the agent — or the host holding the "ask" — proceeds
	// through its normal permission flow.
	return nil
}

// decodeToolInput decodes the built-in tools' tool_input shape. An absent
// tool_input (Cursor's payload has none) decodes to the zero value rather
// than an error; malformed JSON is a real error, since silently treating a
// garbled Bash payload as an empty command would evaluate nothing and allow
// everything.
func (in hookInput) decodeToolInput() (toolWriteInput, error) {
	var out toolWriteInput
	if len(in.ToolInput) == 0 {
		return out, nil
	}
	// Only the tool names whose fields this struct describes are decoded —
	// an MCP tool's arguments are arbitrary, and a type mismatch there
	// (e.g. {"path": 12}) is not Damping's error to report.
	switch in.ToolName {
	case "Bash", "Write", "Edit", "MultiEdit":
		if err := json.Unmarshal(in.ToolInput, &out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func buildHookActionEvent(kind hookActionKind, eventID, sessionID, actor, target, rawCommand, factsRaw string, d decision.Decision) event.ActionEvent {
	switch kind {
	case actionConfigWrite:
		return hookadapter.BuildConfigWriteActionEvent(eventID, sessionID, actor, target, factsRaw, d)
	case actionMCPToolCall:
		return hookadapter.BuildToolCallActionEvent(eventID, sessionID, actor, target, factsRaw, d)
	default:
		return hookadapter.BuildActionEvent(eventID, sessionID, actor, rawCommand, d)
	}
}

func hookChannel(kind hookActionKind) event.Channel {
	if kind == actionMCPToolCall {
		return event.ChannelMCP
	}
	return event.ChannelCLI
}

func hookActionType(kind hookActionKind) event.ActionType {
	switch kind {
	case actionConfigWrite:
		return event.ActionConfigWrite
	case actionMCPToolCall:
		return event.ActionToolCall
	default:
		return event.ActionShellExec
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// hookResponder owns everything about answering one hook invocation: the
// audit sink, and — in `--hook-json` mode — the single JSON object written
// to stdout. Every early return in runHook goes through it, because a host
// that gets no output at all cannot tell "Damping allowed this" from
// "Damping crashed" — see features/gui_host_integration.feature.
type hookResponder struct {
	cmd          *cobra.Command
	opts         hookOptions
	writer       *audit.Writer
	hasAuditSink bool
	dialect      hookadapter.HostDialect
}

// respond writes the host-facing JSON body, exactly once, in host mode
// only. In ordinary (terminal agent) mode it is a no-op: stdout there
// belongs to the agent's own protocol.
func (h *hookResponder) respond(in hookadapter.HostResponseInput) {
	if !h.opts.hostJSON {
		return
	}
	in.Dialect = h.dialect
	if in.Dialect == "" {
		in.Dialect = hookadapter.DialectClaudeCode
	}
	in.Version = Version
	if err := hookadapter.WriteHostResponse(h.cmd.OutOrStdout(), hookadapter.BuildHostResponse(in)); err != nil {
		fmt.Fprintf(h.cmd.ErrOrStderr(), "damping: failed to write hook response: %v\n", err)
	}
}

// noObjection ends the invocation with "Damping is not holding this back" —
// used for the paths where no policy decision was made at all (a tool
// Damping doesn't judge, enforcement switched off). The reason is carried
// for the host's benefit only; it deliberately does not become an audit
// record, because nothing was evaluated.
func (h *hookResponder) noObjection(reason string) error {
	h.respond(hookadapter.HostResponseInput{
		Decision: decision.Decision{Verdict: decision.Allow, Reason: reason},
	})
	return nil
}

// degraded records an internal failure and answers the caller. Always
// returns nil: a degradation fails open by design (docs/threat-model.md
// §6), loudly rather than silently.
func (h *hookResponder) degraded(sessionID, actor, reason string) error {
	eventID := event.NewID()
	logDegradedWithID(h.cmd, h.writer, h.hasAuditSink, eventID, sessionID, actor, reason)
	h.respond(hookadapter.HostResponseInput{
		Decision: decision.Decision{Verdict: decision.Allow, Degraded: true, Reason: reason},
		EventID:  eventID,
		Channel:  event.ChannelCLI,
	})
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
//
// In `--hook-json` mode runHook only reaches this for a risk tier the
// operator actually configured: there, an unconfigured tier means "hand it
// to the host to ask", not "deny", since a human is available after all.
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
// Facts-direct paths (Write/Edit/MultiEdit, and MCP tool calls): engine.Evaluate
// itself runs regexes against a full file's contents (see
// core/policy/rules_configwrite.go) or an arbitrary MCP argument object,
// untrusted input in the same sense shell.Analyze's is, so it gets the same
// fail-open-and-degraded treatment on a panic rather than crashing this
// subprocess.
func evaluateFactsRecovering(f policy.Facts, engine policy.Evaluator) (d decision.Decision, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("policy.Evaluate panicked: %v", r)
		}
	}()
	return engine.Evaluate(f), nil
}

// truncateForDisplay bounds how much of a Write/Edit/MultiEdit's content —
// or an MCP tool call's arguments — reaches the terminal:
// ui.TTYPrompter.Confirm prints its argument verbatim on a single
// "Command: %s" line with no truncation of its own (unlike a shell command,
// file content and tool arguments can be arbitrarily large/multi-line and
// would otherwise blow out the confirmation prompt's layout). This only
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
	logDegradedWithID(cmd, writer, hasAuditSink, event.NewID(), sessionID, actor, reason)
}

// logDegradedWithID is logDegraded with the event id chosen by the caller,
// so a host-facing response can name the very audit record this wrote.
func logDegradedWithID(cmd *cobra.Command, writer *audit.Writer, hasAuditSink bool, eventID, sessionID, actor, reason string) {
	if hasAuditSink {
		if err := writer.Append(degradedEvent(eventID, sessionID, actor, reason)); err == nil {
			return
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "damping: %s\n", reason)
}

func degradedEvent(eventID, sessionID, actor, reason string) event.ActionEvent {
	return hookadapter.BuildActionEvent(eventID, sessionID, actor, "", decision.Decision{
		Verdict:  decision.Allow,
		Degraded: true,
		Reason:   reason,
	})
}
