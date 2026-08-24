Feature: Embedding Damping in a GUI host
  As the author of a desktop app that embeds an AI coding/writing agent
  I want Damping to hand a Prompt-tier decision back to my own confirmation UI
  So that a GUI user gets a real allow/deny choice where a terminal-less host would otherwise get an unexplained hard block

  # Why this exists at all. Damping's own confirmation prompt (§12 of
  # docs/cli-reference.md) talks to the controlling terminal directly, and a
  # Prompt-tier decision with no terminal to ask defaults to deny. That is
  # the right default for an unattended CLI agent, but it is the *wrong*
  # default for a desktop app embedding an agent SDK: there is a human
  # sitting right there, the host has a perfectly good permission dialog,
  # and every Prompt-tier rule (most of the shipped default policy) would
  # otherwise turn into a silent hard block with no way for that human to
  # say yes.
  #
  # This is deliberately an explicit opt-in flag and never an automatic
  # consequence of "no TTY was found" — see the parked experiment on branch
  # experiment/tty-ask-fallback (2026-07-06) and docs/threat-model.md §6.1:
  # Claude Code's own "auto" permission mode silently treats an "ask"
  # response as allow, and Cursor's shipped ask handling has been reported
  # to execute the command with no prompt at all. Both fail in the unsafe
  # direction, so a hook that guesses its way into "ask" is a downgrade.
  # A host that passes --hook-json is making a promise instead: "I will
  # render this question to a human myself."

  Background:
    Given Damping is running with the default policy

  Scenario: A Prompt-tier decision is deferred to the host's own confirmation UI
    Given the host runs the hook with "--hook-json"
    When the host's agent asks to run "rm -rf ~/"
    Then Damping should exit 0 so the host stays in control of the outcome
    And the hook response should carry permissionDecision "ask"
    And the hook response should name the matched rule "destructive.rm_rf_protected"
    And the audit record should show the action was deferred to the host, not resolved

  Scenario: A hard deny is still a hard deny in host mode
    Given the host runs the hook with "--hook-json"
    When the host's agent asks to run "damping off"
    Then Damping should exit 2
    And the hook response should carry permissionDecision "deny"
    # Host mode changes what happens to a *Prompt*-tier decision and nothing
    # else. A deny-tier rule is not a question, so there is nothing to ask a
    # human about — the host gets the same exit code 2 every other agent
    # gets, plus a machine-readable reason it can show in its own UI.

  Scenario: An allowed action never claims "allow" on the host's behalf
    Given the host runs the hook with "--hook-json"
    When the host's agent asks to run "git status"
    Then Damping should exit 0 so the host stays in control of the outcome
    And the hook response should carry no permissionDecision at all
    And the hook response should report the Damping decision "allow"
    # "Damping has no objection" is not the same statement as "approved" —
    # in the Claude Code hook contract an explicit permissionDecision:
    # "allow" *skips the host's own permission flow entirely*. Damping never
    # emits that: a guardrail may hold an action back, but it has no
    # business auto-approving one on the user's behalf. The host still runs
    # whatever policy it has of its own.

  Scenario: Host mode is opt-in — without the flag, a terminal-less Prompt still denies
    When the host's agent asks to run "rm -rf ~/"
    Then Damping should exit 2
    # Same input, same policy, no flag: the historical fail-closed behavior
    # is untouched for every existing CLI install.

  Scenario: An operator's noninteractive_prompt_fallback still wins over deferral
    Given the policy resolves medium-risk prompts to allow when nobody can be asked
    And the host runs the hook with "--hook-json"
    When the host's agent asks to run "chmod -R 777 /var/www"
    Then Damping should exit 0 so the host stays in control of the outcome
    And the hook response should carry no permissionDecision at all
    # An operator who has already settled a risk tier in policy.yaml has
    # answered the question in advance; re-asking a human who was told they
    # would not be asked is not "safer", just noisier.

  Scenario: The host labels itself in the shared audit trail
    Given the host runs the hook with "--hook-json --actor notes-desktop"
    When the host's agent asks to run "damping off"
    Then the audit record's actor should be "notes-desktop"
    # One audit trail across every channel is the whole product promise, and
    # a desktop host's interceptions landing in the same ~/.damping/audit.jsonl
    # as the user's own Claude Code CLI is the point — but only if you can
    # still tell which one did what. Without this the host's payload (a
    # PreToolUse shape with no turn_id) is indistinguishable from the user's
    # own Claude Code session.

  Scenario: An internal degradation still produces a response the host can parse
    Given the host runs the hook with "--hook-json"
    When the host sends a malformed hook payload
    Then Damping should exit 0 so the host stays in control of the outcome
    And the hook response should report that Damping degraded
    # docs/threat-model.md §6: an internal Damping failure fails open, but
    # never silently. A host that gets no output at all cannot tell "allowed"
    # from "crashed", so host mode always answers with something parseable.
