//go:build windows

package cmd

import (
	"errors"

	"github.com/amplify-lab/damping/cli/ui"
)

// openTTYPrompter is not yet implemented on Windows (would need CONIN$/
// CONOUT$ instead of /dev/tty). A Prompt-tier decision on Windows currently
// falls back to Deny-by-default in runHook, same as "no controlling
// terminal" on Unix — this is a known V1 gap, not a silent one, tracked for
// a near-term follow-up rather than faked.
func openTTYPrompter() (ui.TTYPrompter, func(), error) {
	return ui.TTYPrompter{}, nil, errors.New("interactive confirmation prompt not yet implemented on Windows")
}
