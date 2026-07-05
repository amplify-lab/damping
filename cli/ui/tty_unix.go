//go:build !windows

package ui

import "os"

// OpenTTYPrompter opens the controlling terminal directly so an interactive
// confirmation prompt can talk to the human even when the calling
// process's own stdin/stdout are reserved for a different protocol (the
// Claude Code/Cursor hook JSON contract, or the MCP JSON-RPC stream in
// `damping mcp wrap`) — see docs/architecture.md §6.
func OpenTTYPrompter() (Prompter, func(), error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	return TTYPrompter{In: tty, Out: tty}, func() { _ = tty.Close() }, nil
}
