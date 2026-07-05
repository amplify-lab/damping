package cmd

import (
	"fmt"
	"net"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/amplify-lab/damping/cli/dashboard"
	"github.com/amplify-lab/damping/cli/paths"
)

func newDashboardCmd() *cobra.Command {
	var (
		host string
		port int
	)
	c := &cobra.Command{
		Use:   "dashboard",
		Short: "Serve a local, read-only web view of your own audit log",
		Long: "damping dashboard starts a small HTTP server on this machine that renders the same\n" +
			"~/.damping/audit.jsonl `damping log` already reads, in a browser instead of a terminal\n" +
			"table. This is NOT the Phase 4 team dashboard (docs/ux-dashboard-spec.md) — no auth, no\n" +
			"team sync, no cloud calls: it binds to 127.0.0.1 by default and the audit log never\n" +
			"leaves this machine. Ctrl+C to stop.",
		RunE: func(cmd *cobra.Command, args []string) error {
			auditPath, err := paths.Audit()
			if err != nil {
				return err
			}
			policyPath, err := resolvePolicyPath()
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if host != "127.0.0.1" && host != "localhost" {
				fmt.Fprintf(w, "⚠  Binding to %s, not just localhost — your audit log (raw commands, agent activity) becomes reachable from anywhere that can reach this host, with no authentication at all.\n", host)
			}

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			fmt.Fprintf(w, "Dashboard running at http://%s (Ctrl+C to stop)\n", addr)

			srv := dashboard.NewServer(dashboard.Config{AuditPath: auditPath, PolicyPath: policyPath, BindHost: host})
			return http.ListenAndServe(addr, srv.Handler()) // #nosec G114 -- a local single-user CLI dev tool, not an internet-facing server; explicit timeouts would add nothing a client-abandoned SSE stream needs
		},
	}
	c.Flags().StringVar(&host, "host", "127.0.0.1", "address to bind to — only change this if you understand the audit log becomes reachable beyond this machine, unauthenticated")
	c.Flags().IntVar(&port, "port", 4243, "port to listen on")
	return c
}
