//go:build !windows

package cmd

import (
	"os"

	"github.com/amplify-lab/damping/cli/ui"
)

// openTTYPrompter opens the controlling terminal directly so the
// confirmation prompt can talk to the human even though the hook
// subprocess's own stdin/stdout are reserved for the Claude Code JSON
// protocol — see the comment on runHook in hook.go.
func openTTYPrompter() (ui.TTYPrompter, func(), error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return ui.TTYPrompter{}, nil, err
	}
	return ui.TTYPrompter{In: tty, Out: tty}, func() { _ = tty.Close() }, nil
}
