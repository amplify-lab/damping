Feature: Policy configuration and dry-run testing
  As a developer or contributor tuning Damping's rules
  I want to inspect and dry-run policy changes without executing real commands
  So that I can verify a new rule before it ships, and reproduce a false positive as a regression test

  Background:
    Given Damping is running with the default policy

  Scenario: Listing the active policy rules
    When the user runs "damping policy list"
    Then the output should show every rule's id, risk level, and default action

  Scenario: Dry-running a command against the policy without executing it
    When the user runs "damping policy test \"rm -rf ~/Documents\""
    Then the output should show the verdict that would result
    And the output should name the matched rule
    And the command should not actually execute

  Scenario: A flagged dry-run test exits with a distinct status for CI use
    When the user runs "damping policy test \"rm -rf ~/\""
    Then the verdict should be "prompt", not a plain allow
    And the command should exit with status 3
    And an allowed dry-run test such as "damping policy test \"git status\"" should exit with status 0

  Scenario: Validating a policy file catches schema errors before they cause a crash
    Given a policy file with an invalid rule definition
    When the user runs "damping policy validate"
    Then Damping should report which rule id or field is invalid and why
    # "Location" here means which rule/field, not a line:column source position —
    # core/policy/config.go's Validate() names the offending rule id (e.g. an
    # unknown rule id, a duplicate id, or an invalid action value), it does not
    # track byte/line offsets into the YAML file.
    And Damping should not attempt to load the invalid file into the running policy engine

  Scenario Outline: A new rule must have both a "should block" and a "should not block" test case
    Given a new rule "<rule_id>" is proposed
    Then there must be at least one scenario asserting it blocks a real dangerous case
    And there must be at least one scenario asserting it does not block a normal, safe case
    And a rule without both is not permitted to merge

    Examples:
      | rule_id                          |
      | destructive.rm_rf_protected       |
      | destructive.git_push_force        |
      | destructive.encoded_payload_pipe  |
