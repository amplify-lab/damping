package agent

import (
	"path/filepath"
	"testing"
)

// TestRegistry_ContainsClaudeCodeAndCursor is a regression test for the
// registry consolidation (docs/00 §七 item 8): doctor.go/status.go/
// dashboard/handlers.go each used to hand-code a separate branch per agent
// instead of iterating one shared list. This proves the registry itself
// carries working Install/HasHook funcs, not just names.
func TestRegistry_ContainsClaudeCodeAndCursor(t *testing.T) {
	names := map[string]bool{}
	for _, a := range Registry {
		names[a.Name] = true
	}
	if !names["claude-code"] || !names["cursor"] {
		t.Fatalf("expected claude-code and cursor in the registry, got %v", Registry)
	}
}

func TestRegistry_ByName_FindsRegisteredAgent(t *testing.T) {
	a, ok := ByName("cursor")
	if !ok {
		t.Fatal("expected to find \"cursor\" by name")
	}
	if a.DisplayName != "Cursor" {
		t.Fatalf("expected DisplayName \"Cursor\", got %q", a.DisplayName)
	}
}

func TestRegistry_ByName_UnknownNameNotFound(t *testing.T) {
	if _, ok := ByName("nonexistent-agent"); ok {
		t.Fatal("expected an unregistered name to not be found")
	}
}

// TestRegistry_EntriesAreFunctional proves each registry entry's Install
// and HasHook funcs are the real, working per-agent implementations (not
// nil/stub funcs) by actually installing through the registry entry and
// checking it back through the same entry — the same round trip
// InstallClaudeCodeHook/HasClaudeCodeHook's own direct tests already prove,
// but exercised via the registry indirection every real call site now uses.
func TestRegistry_EntriesAreFunctional(t *testing.T) {
	for _, a := range Registry {
		a := a
		t.Run(a.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			if has, err := a.HasHook(path); err != nil {
				t.Fatalf("HasHook on a missing file: %v", err)
			} else if has {
				t.Fatal("expected no hook registered in a fresh file")
			}
			if err := a.Install(path, false); err != nil {
				t.Fatalf("Install: %v", err)
			}
			has, err := a.HasHook(path)
			if err != nil {
				t.Fatalf("HasHook after install: %v", err)
			}
			if !has {
				t.Fatal("expected HasHook to report true immediately after Install")
			}
		})
	}
}
