//go:build windows

package update

import "os/exec"

// setProcessGroup is a no-op on Windows: os/exec's default context-
// cancellation behavior (terminating cmd.Process directly) is what's
// available without a full Job Object implementation, and the windows
// Method only ever runs `powershell -Command "irm ... | iex"` directly —
// there's no curl-pipe-sh grandchild tree the way the script kind has.
func setProcessGroup(cmd *exec.Cmd) {}
