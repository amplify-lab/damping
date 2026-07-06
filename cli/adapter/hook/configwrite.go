package hook

import (
	"strings"

	"github.com/amplify-lab/damping/core/event"
	"github.com/amplify-lab/damping/core/policy"
)

// ToolWriteInput is the minimal shape cli/cmd/hook.go extracts from a
// Claude Code Write/Edit/MultiEdit tool_input — see docs/cli-reference.md
// §11 for the verified field names per tool (Write: file_path/content;
// Edit: file_path/old_string/new_string; MultiEdit: file_path/edits[]).
// Cursor and Codex have no equivalent pre-write hook — see §11's
// capability note — so this only ever gets built from a Claude Code
// payload today.
type ToolWriteInput struct {
	FilePath string
	Content  string // Write
	Edits    []ToolEditOp
}

// ToolEditOp is one old_string/new_string pair — a single edit for the
// "Edit" tool, or one element of "MultiEdit"'s edits array.
type ToolEditOp struct {
	OldString string
	NewString string
}

// FactsFromToolWrite builds Facts for a Write/Edit/MultiEdit tool call —
// the non-shell counterpart to EvaluateCommand's shell-AST path. See
// core/policy/rules_configwrite.go for the rules that match on
// event.ActionConfigWrite.
//
// Raw deliberately carries the file path AND the full new content/edit
// text (not just the path) so content-inspecting rules (e.g.
// destructive.agent_permission_escalation's autoApprove-key check) have
// something to match against — this project's rule matchers work on
// Facts.Raw/Args text, not real JSON parsing, matching the existing
// text-level-signal approach cli/shell's rules already use (see
// rules_shell.go's decodeFlagPatterns for precedent). Known, accepted
// limitation this shares with several existing rules: because a Write
// tool call always carries the entire file's new content (Damping has no
// access to the prior version to diff against), Facts.Raw for a Write can
// be large — see cli/cmd/hook.go's display truncation for why the
// terminal confirmation prompt doesn't show it verbatim, and
// core/audit.Writer.Append's existing 1 MiB Raw cap for why this can't
// grow unbounded in the audit log either.
func FactsFromToolWrite(toolName string, in ToolWriteInput) policy.Facts {
	var content string
	switch toolName {
	case "Write":
		content = in.Content
	case "Edit":
		if len(in.Edits) > 0 {
			content = in.Edits[0].NewString
		}
	case "MultiEdit":
		parts := make([]string, 0, len(in.Edits))
		for _, e := range in.Edits {
			parts = append(parts, e.NewString)
		}
		content = strings.Join(parts, "\n")
	}
	return policy.Facts{
		ActionType: event.ActionConfigWrite,
		Command:    toolName,
		Target:     in.FilePath,
		Raw:        in.FilePath + "\n" + content,
	}
}
