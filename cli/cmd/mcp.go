package cmd

import (
	"github.com/spf13/cobra"

	mcpadapter "github.com/amplify-lab/damping/cli/adapter/mcp"
	"github.com/amplify-lab/damping/cli/i18n"
	"github.com/amplify-lab/damping/core/policy"
)

func newMCPCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "mcp",
		Short: "MCP-related commands",
	}
	c.AddCommand(newMCPWrapCmd())
	return c
}

func newMCPWrapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "wrap -- <server-command...>",
		Short: "Wrap an MCP server so its tool calls go through the same policy engine and audit log as CLI commands",
		Long: "damping mcp wrap launches <server-command> as the real MCP server, re-exposes its tools\n" +
			"unchanged over this process's own stdin/stdout, and runs every outgoing tool call through\n" +
			"the same core/policy engine and core/audit log the CLI hook uses. This is the V1 thin\n" +
			"adapter (see docs/architecture.md §7) — no OAuth, no token re-issuance, no confused-deputy\n" +
			"defense. Configure your MCP client to launch \"damping mcp wrap -- <original command>\"\n" +
			"in place of the real server.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policyPath, err := resolvePolicyPath()
			if err != nil {
				return err
			}
			cfg, err := policy.LoadConfig(policyPath)
			if err != nil {
				return err
			}
			engine, err := policy.NewEvaluator(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			// A review found this used to discard the ok-bool entirely
			// (`writer, _ := newAuditWriter()`), unlike its two sibling call
			// sites (hook.go, onoff.go) — so whenever the audit sink couldn't
			// be constructed (e.g. no HOME in a sandboxed runner), every MCP
			// tool call for this session's whole lifetime went unaudited with
			// zero indication anything degraded. logDegraded falls back to
			// stderr here since there's no sink to record the degradation in.
			writer, hasAuditSink := newAuditWriter()
			if !hasAuditSink {
				logDegraded(cmd, writer, hasAuditSink, "unknown", "mcp-client", "constructing audit writer: no audit sink available; MCP tool calls for this session will not be recorded")
			}

			return mcpadapter.Wrap(cmd.Context(), args, engine, policyPath, i18n.ResolveLang(cfg.UILanguage), writer, "mcp-client")
		},
	}
}
