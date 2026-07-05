Feature: MCP tool-call governance (V1 thin adapter)
  As a developer whose AI agent calls MCP tools
  I want MCP tool calls checked by the same policy engine and written to the same audit log as CLI commands
  So that "one policy, one audit trail, every channel" is true in practice, not just marketing copy

  Background:
    Given Damping is running with the default policy
    And the agent's MCP server is launched via "damping mcp wrap"

  Scenario: A tool the server itself declares destructive is intercepted
    Given the "filesystem.delete_all" tool is annotated with destructiveHint=true
    When the agent calls MCP tool "filesystem.delete_all" with args {"path":"/data"}
    Then Damping should intercept the call
    And the matched rule should be "mcp.destructive_tool_call"
    # This is the individual-tier-appropriate MCP rule: it needs no identity
    # system, since the signal comes from the server's own tool annotation
    # (MCP's standard ToolAnnotations.DestructiveHint), not from who is calling.

  Scenario: A read-only tool call is allowed without interrupting the user
    When the agent calls MCP tool "database.read_record" with args {"table":"users","id":"42"}
    Then Damping should allow the call immediately

  @phase5
  Scenario: A write-tagged tool call with no bound identity is intercepted (Phase 5 enterprise policy — not active in the V1 individual-tier default)
    Given the "database.delete_record" tool is tagged as a write tool
    And an enterprise identity system is bound (unlike the individual tier, which has none)
    And the calling session has no bound identity
    When the agent calls MCP tool "database.delete_record" with args {"table":"users","id":"*"}
    Then Damping should intercept the call
    And the matched rule should be "mcp.write_tool_unscoped_identity"
    # NOTE: this rule is implemented (core/policy/rules.go) but deliberately
    # NOT included in cli/policies/default.yaml's active rule list — with no
    # identity system in the individual tier, ActionEvent.Identity is always
    # empty, so this would fire on nearly every non-read-only MCP tool call.
    # See docs/cli-reference.md §13 and docs/00-統一開發計畫（定案版）.md.

  Scenario: An "always allow" choice for an MCP tool call is honored for the rest of the session
    Given the agent calls MCP tool "filesystem.delete_all" with args {"path":"/data"}
    And the user chooses "Always allow this exact command" at the confirmation prompt
    When the agent calls MCP tool "filesystem.delete_all" with args {"path":"/data"} again, in the same "damping mcp wrap" session
    Then Damping should allow the second call immediately, without prompting again
    # damping mcp wrap is one long-lived process for the whole MCP session,
    # unlike the one-shot CLI hook subprocess, which simply re-reads
    # policy.yaml on its next invocation — an in-memory overlay on top of
    # the same on-disk persistence makes "always" true within this session
    # too, not only for a hypothetical future "damping mcp wrap" run.

  Scenario: CLI and MCP events land in the same audit log
    Given the agent has just triggered a CLI interception for "rm -rf ~/"
    And the agent has just triggered an MCP interception for "database.delete_record"
    When the user runs "damping log"
    Then both events should appear in the same audit output
    And filtering with "damping log --channel cli" should show only the CLI event
    And filtering with "damping log --channel mcp" should show only the MCP event
    And both events should share the same ActionEvent schema

  Scenario: The V1 MCP adapter does not perform OAuth or token re-issuance
    Given the agent's MCP client presents a token scoped to "server-a"
    When "damping mcp wrap" forwards a tool call to the wrapped server
    Then Damping should not inspect, validate, or re-issue any OAuth token
    And Damping should only evaluate the tool name and arguments against policy
    # Full OAuth 2.1 + confused-deputy defense is Phase 3 (gateway/), not V1.
    # See docs/architecture.md §7 and docs/00-統一開發計畫（定案版）.md §四修正三.

  @phase3
  Scenario: Confused deputy defense (Gateway, Phase 3 — not implemented in V1)
    Given an agent holds a token scoped to "ServerA"
    When the agent attempts to call a tool on "ServerB" using that token
    Then the Gateway should reject the call because the audience does not match
    And the audit log should record the rejection reason

  @phase3
  Scenario: Read-only identity may not invoke a write tool (Gateway, Phase 3 — not implemented in V1)
    Given the agent is connected with a "read-only" bound identity
    When the agent calls MCP tool "database.delete_record"
    Then the Gateway should deny the call
    And the audit log should record actor, identity, tool, and decision
