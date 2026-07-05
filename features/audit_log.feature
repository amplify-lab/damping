Feature: Single-source-of-truth audit log
  As a developer or team admin
  I want every intercepted action recorded in one consistent format
  So that the audit trail can be trusted, filtered, and eventually fed into compliance reports

  Background:
    Given Damping is running with the default policy

  Scenario: Adapters never write audit records directly
    Given the CLI adapter has just normalized a shell command into an ActionEvent
    And the MCP adapter has just normalized a tool call into an ActionEvent
    When each adapter hands its ActionEvent to core/audit
    Then core/audit should be the only component that appends to ~/.damping/audit.jsonl
    And neither adapter should write to the audit file directly

  Scenario: Every audit record contains the fields required for a future compliance report
    Given an action has just been intercepted
    When the resulting ActionEvent is written to the audit log
    Then the record should include event_id, actor, identity, channel, action_type, target, raw, parsed_args, risk_level, decision, policy_id, session_id, and timestamp
    And identity may be empty in the individual tier without breaking the schema

  Scenario: A prompt that the user resolves produces one coherent record, not two
    Given a command triggered a "prompt" decision
    When the user chooses "Allow once"
    Then the audit log should show a single event with decision "prompt→allow"
    And it should not appear as two separate, disjoint entries

  Scenario: Filtering the log by channel demonstrates cross-channel unification
    Given the audit log contains both cli and mcp events from the same session
    When the user runs "damping log --channel mcp"
    Then only mcp-channel events should be shown
    And this filter should require no separate storage backend per channel

  Scenario: An internal failure is logged as degraded, not silently dropped
    Given the shell parser crashes while analyzing a command
    When the surrounding agent fails open per its own hook contract
    Then Damping should still write an audit record with decision.degraded = true
    And "damping doctor" should surface this as a warning on the next run

  Scenario: Empty query results are communicated clearly
    When the user runs "damping log --channel mcp" and no MCP events exist yet
    Then the output should read "No audit events matched those filters."
    And the output should not be a blank screen

  Scenario: The local audit log never leaves the machine by default
    Given Damping has not been opted into team sync
    When any action is intercepted
    Then the resulting ActionEvent should be written only to ~/.damping/audit.jsonl
    And no network request should be made to transmit the event

  @phase4
  Scenario: An opted-in team member's events reach the team dashboard (Phase 4 — not implemented in V1)
    Given team member "alice" has run "damping sync enable"
    And team member "bob" has not opted in
    When alice's agent triggers an interception
    Then the event should appear in the team dashboard's live stream
    And no data from bob's machine should ever appear in the dashboard
