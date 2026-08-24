package hook

import (
	"encoding/json"
	"testing"

	"github.com/amplify-lab/damping/core/event"
)

func TestIsMCPToolName(t *testing.T) {
	cases := map[string]bool{
		"mcp__notes__delete_file": true,
		"mcp__acme__read":         true,
		"Bash":                    false,
		"Write":                   false,
		"mcp_notes_delete_file":   false, // single underscores: not the agent's namespacing convention
		"":                        false,
	}
	for name, want := range cases {
		if got := IsMCPToolName(name); got != want {
			t.Errorf("IsMCPToolName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestFactsFromMCPToolCall_ShapeMatchesTheWrapChannel(t *testing.T) {
	f := FactsFromMCPToolCall("mcp__notes__delete_file", json.RawMessage(`{"path":"/books/notes.md"}`), nil)

	if f.Channel != event.ChannelMCP {
		t.Errorf("Channel = %q, want %q — an MCP call is an MCP call whichever transport told Damping about it", f.Channel, event.ChannelMCP)
	}
	if f.ActionType != event.ActionToolCall {
		t.Errorf("ActionType = %q, want %q", f.ActionType, event.ActionToolCall)
	}
	if f.Command != "mcp__notes__delete_file" {
		t.Errorf("Command = %q, want the tool name", f.Command)
	}
	// The same "<tool name> <args json>" Raw cli/adapter/mcp's rawCallSummary
	// produces, so an always-allow pattern persisted on one channel matches
	// the same call arriving on the other.
	if want := `mcp__notes__delete_file {"path":"/books/notes.md"}`; f.Raw != want {
		t.Errorf("Raw = %q, want %q", f.Raw, want)
	}
	if f.HasIdentity {
		t.Error("HasIdentity must stay false in the individual tier")
	}
}

func TestFactsFromMCPToolCall_NormalizesArgumentFormatting(t *testing.T) {
	spaced := FactsFromMCPToolCall("mcp__a__b", json.RawMessage("{\n  \"path\": \"/x\"\n}"), nil)
	compact := FactsFromMCPToolCall("mcp__a__b", json.RawMessage(`{"path":"/x"}`), nil)
	if spaced.Raw != compact.Raw {
		t.Errorf("the same call formatted two ways produced two Raw values (%q vs %q) — an [A] always-allow pattern would then only match one of them", spaced.Raw, compact.Raw)
	}
}

func TestFactsFromMCPToolCall_Target(t *testing.T) {
	cases := []struct {
		name string
		args string
		want string
	}{
		{"path", `{"path":"/books/notes.md"}`, "/books/notes.md"},
		{"file_path wins over path", `{"path":"/b","file_path":"/a"}`, "/a"},
		{"array of paths takes the first", `{"paths":["/a","/b"]}`, "/a"},
		{"url", `{"url":"https://example.com/x"}`, "https://example.com/x"},
		{"table", `{"table":"users"}`, "users"},
		{"no recognized key falls back to the tool name", `{"scope":"all"}`, "mcp__acme__sync"},
		{"non-string value falls back", `{"path":12}`, "mcp__acme__sync"},
		{"empty string value falls back", `{"path":""}`, "mcp__acme__sync"},
		{"no arguments at all", ``, "mcp__acme__sync"},
		{"unparseable arguments", `not json`, "mcp__acme__sync"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := FactsFromMCPToolCall("mcp__acme__sync", json.RawMessage(c.args), nil)
			if f.Target != c.want {
				t.Errorf("Target = %q, want %q", f.Target, c.want)
			}
		})
	}
}

func TestFactsFromMCPToolCall_UnparseableArgumentsStillReachThePolicyEngine(t *testing.T) {
	// Garbage arguments are not a reason to drop the call on the floor: the
	// raw text still belongs in front of the human at the prompt and in the
	// audit record, and rules that scan Facts.Raw still get to see it.
	f := FactsFromMCPToolCall("mcp__acme__sync", json.RawMessage(`{"broken`), nil)
	if want := `mcp__acme__sync {"broken`; f.Raw != want {
		t.Errorf("Raw = %q, want %q", f.Raw, want)
	}
}

func TestFactsFromMCPToolCall_Annotations(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name string
		ann  *MCPToolAnnotations
		want []string
	}{
		{"absent annotations are not a read-only claim", nil, []string{"write"}},
		{"explicit destructive hint", &MCPToolAnnotations{DestructiveHint: &yes}, []string{"destructive", "write"}},
		{"explicit read-only hint", &MCPToolAnnotations{ReadOnlyHint: &yes}, []string{"read"}},
		{"explicitly false hints are not the same as absent ones", &MCPToolAnnotations{DestructiveHint: &no, ReadOnlyHint: &no}, []string{"write"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FactsFromMCPToolCall("mcp__a__b", nil, c.ann).ToolTags
			if len(got) != len(c.want) {
				t.Fatalf("ToolTags = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("ToolTags = %v, want %v", got, c.want)
				}
			}
		})
	}
}
