//go:build !windows

package ui

import (
	"os"

	"github.com/amplify-lab/damping/cli/i18n"
)

// OpenTTYPrompter opens the controlling terminal directly so an interactive
// confirmation prompt can talk to the human even when the calling
// process's own stdin/stdout are reserved for a different protocol (the
// Claude Code/Cursor hook JSON contract, or the MCP JSON-RPC stream in
// `damping mcp wrap`) — see docs/architecture.md §6. lang is the resolved
// display language (i18n.ResolveLang(cfg.UILanguage), already resolved by
// the caller — this function doesn't itself know about policy.Config) for
// the returned Prompter's own labels and rule-reason translation.
func OpenTTYPrompter(lang i18n.Lang) (Prompter, func(), error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	return TTYPrompter{In: tty, Out: tty, Lang: lang}, func() { _ = tty.Close() }, nil
}
