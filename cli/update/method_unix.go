//go:build !windows

package update

import (
	"os/exec"
	"syscall"
	"time"
)

// setProcessGroup configures cmd so a canceled context kills the whole
// process tree Apply spawns, not just the immediate child — see Apply's own
// comment for why that matters (curl-pipe-sh's grandchildren otherwise
// survive). Putting the child in its own process group (Setpgid) and
// sending the kill to the negative PID (the whole group, per POSIX kill(2))
// on cancel is the standard fix; see os/exec's Cmd.Cancel/WaitDelay docs.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	// Without WaitDelay, Cmd.Wait blocks indefinitely if the group's kill
	// somehow doesn't fully reap it — bounds that wait instead of hanging
	// `damping update` forever on a canceled context.
	cmd.WaitDelay = 5 * time.Second
}
