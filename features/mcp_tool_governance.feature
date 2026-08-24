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

  Scenario: A tool whose own name declares what it destroys is intercepted without any annotation
    When the agent calls MCP tool "mcp__notes__delete_file" with args {"path":"/books/notes.md"}
    Then Damping should intercept the call
    And the matched rule should be "mcp.destructive_tool_name"
    # The annotation-driven rule above is the honest signal, but most real
    # servers never set ToolAnnotations at all (see cli/adapter/mcp/facts.go's
    # toolTags comment, which is why "assume destructive when unannotated"
    # was rejected). A tool that spells "delete" in its own name is a
    # different, much narrower claim than "unannotated, therefore suspect":
    # the server named the verb itself. Prompt-tier, so one [A] answer
    # retires it for good.

  Scenario: A tool whose name only mentions a destroyed thing in passing is not flagged
    When the agent calls MCP tool "mcp__github__list_deleted_branches" with args {"repo":"acme/web"}
    Then Damping should allow the call immediately
    # The other direction, and the reason matching is whole-word rather than
    # substring: "deleted" is what the returned records are, not what this
    # call does. A rule that fires here is a false positive, and false
    # positives are what get a guardrail uninstalled (docs/threat-model.md).

  Scenario: A tool the server declares read-only is never flagged by its name alone
    Given the "mcp__db__delete_dry_run" tool is annotated with readOnlyHint=true
    When the agent calls MCP tool "mcp__db__delete_dry_run" with args {"table":"users"}
    Then Damping should allow the call immediately
    # An explicit server annotation always beats a guess made from the tool's
    # name — the server is the authority on its own tools.

  Scenario: An MCP tool call arriving through the PreToolUse hook channel is evaluated, not ignored
    Given the agent's MCP server is reached over HTTP, so "damping mcp wrap" cannot sit in front of it
    When the agent's host sends the "mcp__notes__delete_file" tool call to "damping hook pretooluse" with args {"path":"/books/notes.md"}
    Then Damping should intercept the call
    And the matched rule should be "mcp.destructive_tool_name"
    And the audit record should be on the "mcp" channel with target "/books/notes.md"
    # "damping mcp wrap" is a stdio proxy: it can only govern MCP servers the
    # agent launches as a subprocess. An HTTP/SSE server is out of its reach
    # entirely — but the agent's PreToolUse hook still fires for that call,
    # with tool_name "mcp__<server>__<tool>". Before this, the hook channel
    # dropped those on the floor (they weren't Bash/Write/Edit/MultiEdit), so
    # the one channel that *could* see them treated them as nothing to judge.

  Scenario: A host that knows its server's annotations can pass them through the hook channel
    Given the host declares the "mcp__acme__sync_workspace" tool has destructiveHint=true
    When the agent's host sends the "mcp__acme__sync_workspace" tool call to "damping hook pretooluse" with args {"scope":"all"}
    Then Damping should intercept the call
    And the matched rule should be "mcp.destructive_tool_call"
    # The hook contract carries no tool annotations — the agent doesn't
    # forward them. A host that already holds the server's tool list (it had
    # to, to call the tool) can attach them as a Damping-specific extension
    # field, which restores the annotation-driven rule on this channel
    # instead of leaving it dependent on how the tool happens to be named.

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

  # The next two scenarios describe real, implemented, already-tested V1
  # behavior, but this file's own step definitions wire them as thin,
  # disclosed pass-throughs rather than re-proving them here — the actual
  # in-memory-transport MCP client/server harness that proves this lives in
  # cli/adapter/mcp/wrap_test.go's TestWrap_PersistsAlwaysAllowChoiceForRestOfSession
  # and TestWrap_PersistsAlwaysDenyChoiceForRestOfSession, whose building
  # blocks are unexported on purpose (kept internal to the package they
  # test). Read those tests, not just this Gherkin, to see this proven.
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

  Scenario: An "always deny" choice for an MCP tool call is honored for the rest of the session
    Given the agent calls MCP tool "filesystem.delete_all" with args {"path":"/data"}
    And the user chooses "Always deny this exact command" at the confirmation prompt
    When the agent calls MCP tool "filesystem.delete_all" with args {"path":"/data"} again, in the same "damping mcp wrap" session
    Then Damping should deny the second call immediately, without prompting again

  Scenario: CLI and MCP events land in the same audit log
    Given the agent has just triggered a CLI interception for "rm -rf ~/"
    And the agent has just triggered an MCP interception for "database.delete_record"
    When the user runs "damping log"
    Then both events should appear in the same audit output
    And filtering with "damping log --channel cli" should show only the CLI event
    And filtering with "damping log --channel mcp" should show only the MCP event
    And both events should share the same ActionEvent schema

  # This scenario's steps are also a disclosed pass-through (see this
  # file's step-definition doc comment) — the design invariant itself is
  # enforced by what code doesn't exist (no token-handling code anywhere
  # in cli/adapter/mcp) rather than something a single dynamic test run
  # proves; see wrap.go's own doc comments for the no-OAuth invariant.
  Scenario: The V1 MCP adapter does not perform OAuth or token re-issuance
    Given the agent's MCP client presents a token scoped to "server-a"
    When "damping mcp wrap" forwards a tool call to the wrapped server
    Then Damping should not inspect, validate, or re-issue any OAuth token
    And Damping should only evaluate the tool name and arguments against policy
    # Full OAuth 2.1 + confused-deputy defense is Phase 3 (gateway/), not V1.
    # See docs/architecture.md §7 and docs/00-統一開發計畫（定案版）.md §四修正三.

  # These two scenarios are also disclosed pass-throughs (see this file's
  # step-definition doc comment): this file only exercises the pure
  # policy.Evaluator level, with no real MCP client/server/transport, but
  # both behaviors below live in cli/adapter/mcp/wrap.go's real per-call tool
  # handler, one level up from anything policy.Evaluate alone can prove.
  # Read the named Go tests, not just this Gherkin, to see them enforced.
  Scenario: "damping off" is respected by the MCP channel, checked on every tool call
    # Regression guard for a real doc/behavior mismatch: docs/cli-reference.md
    # §6 says "damping off" means the agent's commands "will NOT be checked"
    # with no channel qualifier, but damping mcp wrap used to never call
    # enforcement.IsDisabled() at all — see
    # cli/adapter/mcp/wrap_test.go's TestWrap_RespectsOff.
    Given the "filesystem.delete_all" tool is annotated with destructiveHint=true
    And Damping enforcement is off
    When the agent calls MCP tool "filesystem.delete_all" with args {"path":"/data"}
    Then Damping should allow the call immediately without evaluating it

  Scenario: A missing audit sink for the MCP channel is a loud, logged degradation, not a silent one
    # Regression guard: `damping mcp wrap` used to discard the audit-writer
    # construction error entirely, so every tool call for the session went
    # unaudited with zero indication anything degraded — see
    # cli/cmd/cmd_test.go's TestMCPWrap_LogsDegradedWhenAuditSinkUnavailable.
    Given the audit sink cannot be constructed for this session
    When "damping mcp wrap" starts
    Then Damping should print a stderr warning that the audit sink is unavailable

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
