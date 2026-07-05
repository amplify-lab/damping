//go:build windows

package ui

import "errors"

// OpenTTYPrompter is not yet implemented on Windows (would need CONIN$/
// CONOUT$ instead of /dev/tty). A Prompt-tier decision on Windows currently
// falls back to Deny-by-default in the caller (cli/cmd/hook.go,
// cli/adapter/mcp) — a known V1 gap, not a silent one, tracked for a
// near-term follow-up rather than faked.
func OpenTTYPrompter() (Prompter, func(), error) {
	return nil, nil, errors.New("interactive confirmation prompt not yet implemented on Windows")
}
