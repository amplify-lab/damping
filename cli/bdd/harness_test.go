package bdd

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/amplify-lab/damping/cli/cmd"
)

// runDampingCommand executes the real damping command tree in-process —
// deliberately not a subprocess — shared by every _test.go file in this
// package that needs to drive the actual CLI surface (not just the policy
// engine directly) from a godog step. The command's own error (e.g. an
// ExitCodeError for a hard deny) is returned rather than treated specially;
// callers decide whether that's an expected outcome or a real failure.
func runDampingCommand(stdin string, args ...string) (stdout, stderr string, err error) {
	root := cmd.NewRootCmd()
	var outBuf, errBuf strings.Builder
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

// syncBuffer is a concurrency-safe io.Writer wrapper around bytes.Buffer —
// unlike bytes.Buffer itself, its String() is safe to poll from a step's
// goroutine while a command started via startDampingLogFollow is still
// writing to it in the background. Note: cli/cmd/cmd_test.go shortens
// logFollowPollInterval to a few milliseconds for its own tests, but that
// var is unexported and this package can't reach it — waitForBufferContains
// callers use a generous timeout to comfortably cover the real ~500ms
// default interval instead.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startDampingLogFollow starts `damping log --follow ...` in the background,
// returning concurrency-safe stdout/stderr buffers a step can poll (via
// waitForBufferContains) while the command is still running, and a channel
// that receives its final error once ctx is cancelled and it stops.
func startDampingLogFollow(ctx context.Context, args ...string) (stdout, stderr *syncBuffer, done <-chan error) {
	root := cmd.NewRootCmd()
	stdout, stderr = &syncBuffer{}, &syncBuffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetIn(strings.NewReader(""))
	root.SetArgs(args)
	doneCh := make(chan error, 1)
	go func() { doneCh <- root.ExecuteContext(ctx) }()
	return stdout, stderr, doneCh
}

// waitForBufferContains polls buf until its content contains substr or
// timeout elapses.
func waitForBufferContains(buf *syncBuffer, substr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), substr) {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %v waiting for %q, got:\n%s", timeout, substr, buf.String())
}
