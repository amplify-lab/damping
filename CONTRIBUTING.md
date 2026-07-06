# Contributing to Damping

Thank you for considering a contribution. The two most valuable things you can bring us are:

1. **A false positive** — a normal, everyday command that Damping wrongly flagged. This is the single most important kind of bug report for a tool like this (see `docs/threat-model.md`: false positives are what get a security tool uninstalled).
2. **A bypass** — a way to construct a genuinely dangerous command that Damping's default policy fails to catch.

Both should become a permanent, non-negotiable regression scenario — never a silent one-off fix.

## Before you start

See [`CLAUDE.md`](CLAUDE.md) for the repository map and build/test commands.

## BDD, scenario-first

This project's own governing rule is **情境通過才算完成** — "a scenario only counts as done once it passes." A feature isn't considered built until its Gherkin acceptance criteria are wired to real code and green.

- **`features/*.feature`** — Gherkin, one scenario per acceptance criterion, written in plain English.
- **`cli/bdd/*_test.go`** — the real step-definition wiring via [`cucumber/godog`](https://github.com/cucumber/godog), one file per feature file, run by a plain `go test ./...` from `cli/`.

## Adding or changing a policy rule

Every rule needs **both**:
1. A scenario in `features/dangerous_command.feature` (or `mcp_tool_governance.feature`) asserting it **blocks** a real dangerous case.
2. A scenario asserting it does **not** block a normal, safe case.

A rule without both directions of test coverage will not be merged. Add the matcher function in `core/policy/rules*.go`, register it in the `matchers` map, add the rule's metadata (including `risk:`, one of `low`/`medium`/`high`/`critical`) to `cli/policies/default.yaml`, and mirror both directions as Go tests. If the OPA/Rego engine is in scope, keep `core/policy/policy.rego` in sync — `opa_equivalence_test.go` fails if the two engines ever diverge.

Every behavioral fix should be mutation-tested before being considered done: temporarily revert it, confirm the relevant test now fails for the right reason, restore it, confirm green again.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, ...) — this project publishes an automatic changelog from commit history, so message quality matters.

## Code of conduct

Be direct, be kind, assume good faith. Disagreements about whether something is a false positive or a real bypass are exactly the kind of thing worth arguing about carefully — that's the core product discipline, not just a community norm.
