package cmd

import "fmt"

// ExitCodeError lets a command signal a specific process exit code (see
// docs/cli-reference.md §2) without calling os.Exit directly inside RunE.
// Calling os.Exit from deep inside command logic would make that logic
// untestable in-process (it kills the test binary itself) — main.go is the
// only place that actually terminates the process, by inspecting the error
// Execute() returns.
type ExitCodeError struct {
	Code    int
	Message string
}

func (e *ExitCodeError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("exit code %d", e.Code)
}
