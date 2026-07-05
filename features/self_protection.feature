Feature: Damping cannot be silently disabled
  As a developer relying on Damping for protection
  I want to be the only one who can turn enforcement off, and always know when it happened
  So that an agent cannot discover and quietly remove its own safety layer (the Ona failure mode)

  Background:
    Given Damping is running with the default policy
    And Damping is enabled

  Scenario: "damping off" is an explicit, logged, human action
    When a human runs "damping off" at the terminal
    Then Damping enforcement should stop
    And Damping should print a clearly visible warning that protection is off
    And the audit log should record an event with action_type "self_disable"

  Scenario: "damping off --for" automatically re-enables after the given duration
    When a human runs "damping off --for 30m"
    Then Damping enforcement should stop for 30 minutes
    And Damping should automatically re-enable itself afterward without further input

  Scenario: The agent's own attempt to run "damping off" is denied, not just discouraged
    When the agent attempts to execute "damping off" via its own Bash tool call
    Then Damping should intercept the command
    And the matched rule should be "self_protection.damping_off_attempt"
    And Damping should deny the command
    # This is enforced by an actual policy rule (core/policy/rules_selfprotection.go),
    # not merely a convention — a human running "damping off" directly at their own
    # terminal never reaches this rule at all, since it never goes through the hook.

  Scenario: Harmless damping subcommands are not swept up by the self-protection rule
    When the agent attempts to execute "damping status" via its own Bash tool call
    Then Damping should allow the command immediately

  Scenario: Hook removal outside "damping off" is detected and surfaced
    Given Damping's hook entry was present in "~/.claude/settings.json" during the last "damping doctor" run
    When something other than "damping off" removes that hook entry
    And the human runs "damping doctor" again
    Then doctor should report the hook as missing
    And doctor should suggest "damping init --agent claude-code --force" to reinstall

  Scenario: Policy file tampering is surfaced, not silently trusted
    Given "damping doctor" recorded a hash of the active policy file on the last run
    When the policy file's content changes outside of "damping policy edit"
    And the human runs "damping doctor" again
    Then doctor should report that the policy file hash has changed since the last check

  Scenario: An always-deny pattern overrides a broader always-allow pattern
    Given the user has set an always-allow pattern "git *"
    And the user has separately set an always-deny pattern "git push --force*"
    When the agent attempts to execute "git push --force origin main"
    Then Damping should deny the command
    And the more specific always-deny pattern should take precedence over the broader always-allow pattern
