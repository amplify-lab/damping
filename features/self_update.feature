Feature: Self-update — damping update
  As an individual-tier Damping user
  I want `damping update` to tell me the truth about whether a newer release exists
  So that I can trust it instead of a stale "already up to date" that never actually looked

  DAMPING_NO_UPDATE_CHECK exists to quiet the passive, non-alarming background notice
  that other commands (init, status, doctor, dashboard) print on their way to doing
  something else — it must never make an explicit, human-typed `damping update`
  invocation lie "already up to date" without ever having looked, because the user
  asked that exact question on purpose.

  These scenarios are deliberately scoped to what's fully deterministic without live
  network access: every scenario seeds cli/update's on-disk cache directly (the same
  way cli/cmd/cmd_test.go's existing update tests do), so both `damping update` and the
  background notice other commands print read a known, fresh result instead of ever
  reaching the real GitHub API.

  Background:
    Given Damping is running with the default policy

  Scenario: damping update reports already up to date
    Given the update cache reports the current version is the latest
    When the user runs "damping update"
    Then the output should say damping is already up to date

  Scenario: background update notice is suppressed by DAMPING_NO_UPDATE_CHECK
    Given the update cache reports a newer version is available
    And DAMPING_NO_UPDATE_CHECK is set
    When the user runs "damping status"
    Then the output should not mention an available update

  Scenario: explicit damping update still checks when the background check is disabled
    Given the update cache reports a newer version is available
    And DAMPING_NO_UPDATE_CHECK is set
    And the install location needs elevated privileges
    When the user runs "damping update"
    Then the output should report the available update, not a false already-up-to-date
    # "needs elevated privileges" keeps this on the informational branch —
    # damping update never self-execs the real installer in this scenario,
    # only prints it — so this stays deterministic and network-free like
    # every other scenario in this file, not because privilege-checking
    # itself is what's under test here.
