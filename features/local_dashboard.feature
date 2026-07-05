Feature: Local dashboard — a single-machine web view of your own audit log
  As an individual-tier Damping user
  I want to browse my own agent activity in a browser, not just a terminal table
  So that I can scan risk visually without giving up any local-only, zero-infrastructure guarantee

  This is deliberately NOT Phase 4's team dashboard (docs/ux-dashboard-spec.md,
  features/team_dashboard.feature) — there is no SSO, no team sync, no Cloudflare
  backend here. `damping dashboard` reads the exact same ~/.damping/audit.jsonl
  `damping log` already reads, and nothing it renders ever leaves this machine.

  Background:
    Given Damping is running with the default policy

  Scenario: The dashboard summary reflects current enforcement state
    Given Damping enforcement is on with a valid policy loaded
    When a browser requests the dashboard's summary
    Then the summary should report enforcement enabled
    And the summary should report the policy's rule count
    And the summary should report which agents are registered

  Scenario: The dashboard surfaces a policy that fails to load, not a healthy-looking zero
    Given the policy file cannot be loaded
    When a browser requests the dashboard's summary
    Then the summary should report a policy error
    # Mirrors the exact gap `damping status` closed for the terminal UI
    # (cli/cmd/status.go) — the dashboard must not silently show "0 rules"
    # as if that were a normal, healthy state.

  Scenario: Viewing the event stream shows both cli and mcp events together
    Given the audit log contains both cli and mcp events from the same session
    When a browser requests the dashboard's event stream
    Then events from both channels should be included in the response
    # The concrete, in-product proof of "one audit log, two channels" this
    # project has made everywhere else (see features/audit_log.feature) —
    # the dashboard is just another reader of that single source of truth.

  Scenario: Filtering the dashboard uses the same vocabulary as `damping log`
    Given the audit log contains events at every risk level
    When a browser requests the event stream filtered to risk "critical"
    Then only critical-risk events should be included in the response
    # docs/ux-dashboard-spec.md §4: "CLI/dashboard vocabulary parity" — a
    # user who already knows `damping log --risk critical` has already
    # learned the dashboard's filter too, because it's the same parser
    # (core/audit.ParseFilter), not a second independent implementation.

  Scenario: An empty audit log is reported clearly, not as a blank response
    Given no audit events exist yet
    When a browser requests the dashboard's event stream
    Then the response should be an empty list, not an error
    # The client renders this as "No activity yet — nothing to dampen."
    # (docs/ux-dashboard-spec.md §1's empty-state copy) — never a blank
    # screen, the same discipline the terminal `damping log` already
    # follows for its own empty-results case.

  Scenario: New events appear in the live stream without reloading the page
    Given a browser has an open connection to the dashboard's live event stream
    When a new action is intercepted
    Then the new event should be pushed to the open connection without the browser needing to reconnect
    # Server-Sent Events over core/audit.Follow — the same polling-based
    # tail `damping log --follow` already uses, not a new file-watching
    # mechanism to maintain twice.

  Scenario: The dashboard never listens beyond localhost without an explicit, informed choice
    Given the user starts the dashboard with its default settings
    Then it should bind only to 127.0.0.1
    And no unauthenticated network peer should be able to reach the audit log
