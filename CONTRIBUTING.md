# Contributing to Damping

Thank you for considering a contribution. The two most valuable things you can bring us are:

1. **A false positive** — a normal, everyday command that Damping wrongly flagged. This is the single most important kind of bug report for a tool like this (see `docs/threat-model.md` and `docs/00-統一開發計畫（定案版）.md`: false positives are what get a security tool uninstalled).
2. **A bypass** — a way to construct a genuinely dangerous command that Damping's default policy fails to catch.

Both should become a permanent, non-negotiable regression scenario — never a silent one-off fix.

## Before you start

- Read `docs/00-統一開發計畫（定案版）.md` for the current strategic/architectural state of the project (it supersedes the earlier planning docs where they conflict).
- Read `docs/architecture.md` for the module layout and the `ActionEvent`/`Decision` schema.
- Read `docs/threat-model.md` §3 for the known bypass classes and why AST parsing alone doesn't solve all of them.

## Development setup

```
git clone <repo>
cd damping
go work sync          # or: cd core && go mod tidy; cd ../cli && go mod tidy
cd core && go test ./...
cd ../cli && go test ./...
```

Every package should build and test cleanly with `go build ./...`, `go vet ./...`, and `gofmt -l .` producing no output, from both `core/` and `cli/` independently.

## Adding or changing a policy rule

Every rule needs **both**:
1. A scenario in `features/dangerous_command.feature` (or `mcp_tool_governance.feature`) asserting it **blocks** a real dangerous case.
2. A scenario asserting it does **not** block a normal, safe case.

A rule without both directions of test coverage will not be merged — see `features/policy_config.feature`'s own scenario about this. Add the matcher function in `core/policy/rules.go`, register it in the `matchers` map, add the rule's metadata to `cli/policies/default.yaml`, and mirror both directions as Go tests in `core/policy/policy_test.go` and/or `cli/shell/parser_test.go`.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, ...) — this project publishes an automatic changelog from commit history, so message quality matters.

## Code of conduct

Be direct, be kind, assume good faith. Disagreements about whether something is a false positive or a real bypass are exactly the kind of thing worth arguing about carefully — that's the core product discipline, not just a community norm.
