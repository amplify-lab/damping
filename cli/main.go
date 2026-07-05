// Command damping is the CLI binary for product line A — see
// docs/cli-reference.md for the full command surface.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/amplify-lab/damping/cli/cmd"
)

func main() {
	err := cmd.NewRootCmd().Execute()
	if err == nil {
		return
	}

	var exitErr *cmd.ExitCodeError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.Code)
	}

	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
