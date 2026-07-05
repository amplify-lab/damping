// Package enforcement answers the one question every entrypoint that cares
// whether Damping is currently protecting anything needs to ask: is
// enforcement on or off right now? It's a separate package (not folded into
// cli/cmd) specifically so non-cobra entrypoints — today, the local
// dashboard's HTTP handlers (cli/dashboard) — can ask the identical question
// the CLI commands do without importing the cmd package and risking an
// import cycle back into it.
package enforcement

import (
	"os"
	"strings"
	"time"

	"github.com/amplify-lab/damping/cli/paths"
)

// IsDisabled reports whether enforcement is currently off, respecting an
// expired --for duration (auto re-enable) by treating it as already on.
// Shared by `damping status`, `damping doctor`, the hook entrypoint, the MCP
// wrap adapter (checked fresh on every tool call, not just once at process
// startup — see cli/adapter/mcp/wrap.go), and the local dashboard's summary
// panel.
func IsDisabled() (bool, error) {
	marker, err := paths.DisabledMarker()
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(marker) // #nosec G304 -- marker is paths.DisabledMarker()'s fixed ~/.damping/disabled path (or $DAMPING_HOME override), not an attacker-influenced path
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	var until time.Time
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "until="); ok {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				until = t
			}
		}
	}
	if !until.IsZero() && time.Now().After(until) {
		_ = os.Remove(marker)
		return false, nil
	}
	return true, nil
}
