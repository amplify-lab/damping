@phase5
Feature: Enterprise compliance reporting (Phase 5 — not implemented in V1)
  As a bank's security officer running Damping Enterprise on-prem
  I want to export an audit report in the format our regulator expects
  So that we can demonstrate governance over what our AI agents did, to whom, and why

  Background:
    Given Damping Enterprise is deployed on-prem with identity bound to the bank's AD/LDAP
    And 30 days of agent action history exist in the append-only PostgreSQL audit store

  Scenario: Exporting a regulator-format compliance report
    When the security officer requests a compliance report export
    Then the system should generate a report in the specified regulatory format
    And the report should include, for every high-risk action, the actor, bound identity, channel, timestamp, decision, and outcome

  Scenario: Audit records cannot be altered by any role, including administrators
    Given an audit record exists for a denied high-risk action
    When any user, including an administrator, attempts to UPDATE or DELETE that record
    Then the operation should be rejected by the database schema itself
    And the rejection should be independent of application-level permission checks

  Scenario: A read-only bound identity cannot invoke a write-tagged tool
    Given an agent session is bound to a "read-only" enterprise identity
    When that agent attempts to call a write-tagged MCP tool
    Then the Gateway should deny the call
    And the audit record should show the bound identity that was denied

  Scenario: Data never leaves the customer's internal network
    Given Damping Enterprise is deployed inside the bank's internal network
    When any action is intercepted, evaluated, or logged
    Then no audit data, policy data, or identity data should be transmitted outside that network boundary
