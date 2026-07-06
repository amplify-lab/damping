Feature: Early compliance-report demo (V1 CLI, not the Phase 5 enterprise feature)

  # This is deliberately NOT an implementation of
  # features/compliance_report.feature — that feature's own Background
  # requires Damping Enterprise deployed on-prem with identity bound to a
  # bank's AD/LDAP and 30 days of history in an append-only PostgreSQL
  # store, none of which exists yet (Phase 5 is not built). This feature
  # covers a much smaller, honestly-scoped capability shipped ahead of that:
  # a `damping compliance-report` command that formats the *already-shipped*
  # local audit trail (core/audit, event.ActionEvent) into a compliance-
  # report-shaped document, plus a synthetic demo dataset so the report is
  # demoable to a prospective customer before any real customer has
  # installed anything. See docs/00-統一開發計畫（定案版）.md §七 item 15
  # (M1) for why this, specifically, is the fastest real artifact to show a
  # prospect — it needs no new infrastructure, just a new view over data
  # Damping already collects.
  #
  # Grounded in real market research (2026-07-07): Taiwan's FSC has not
  # published a fixed compliance-report template (still "studying" an
  # Agentic-AI-specific guideline as of this feature's writing), so this
  # command does not claim to produce an "official 金管會格式" document —
  # it produces one report structure informed by what FSC's existing AI
  # guidelines and the passed AI Basic Law's accountability principles both
  # emphasize (a traceable actor/identity/decision record for high-risk
  # automated actions), and says so in its own output.

  Background:
    Given Damping is running with the default policy

  Scenario: Generating a demo compliance report needs no real audit history
    When the user runs "damping compliance-report demo"
    Then the report should be generated from a synthetic 30-day dataset, not the real local audit log
    And the report should clearly label itself as a demo built on synthetic data
    And the report should include, for every high-risk or critical synthetic action, the actor, bound identity, channel, timestamp, matched rule, decision, and outcome
    And every matched rule referenced in the report should be a real rule id from cli/policies/default.yaml

  Scenario: The demo report discloses what it is not
    When the user runs "damping compliance-report demo"
    Then the report should state that it is not an official regulator-issued report template
    And the report should state that it is not the same as the full Phase 5 enterprise compliance report (on-prem, AD/LDAP-bound identity, append-only PostgreSQL history)

  Scenario Outline: The demo report can be rendered in multiple formats
    When the user runs "damping compliance-report demo --format <format>"
    Then the output should be valid <format>

    Examples:
      | format   |
      | markdown |
      | json     |
      | text     |

  Scenario: Exporting a real compliance report from the actual local audit log
    Given the local audit log contains a mix of allowed, denied, and prompt-resolved events across multiple actors
    When the user runs "damping compliance-report export"
    Then the report should be generated from the real local audit log, not synthetic data
    And the report should include every high-risk or critical action from that log with its actor, identity (if bound), channel, timestamp, matched rule, decision, and outcome
    And low-risk allowed actions should not clutter the high-risk section, but should still be reflected in the summary counts

  Scenario: Exporting a real compliance report with no matching history is handled clearly
    Given the local audit log has no high-risk or critical events in the requested period
    When the user runs "damping compliance-report export"
    Then the report should clearly state that no high-risk or critical actions occurred in the period
    And this should not be rendered identically to a report that actually found and is hiding such actions
