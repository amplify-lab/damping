# Damping — engineering notes for AI agents and contributors

This file is for anyone (human or AI agent) working *on* this codebase. If you're looking for how to *use* Damping, see [`README.md`](README.md) instead.

## Read first

- [`docs/architecture.md`](docs/architecture.md) — module layout, the `ActionEvent`/`Decision` schema, why `core/` and `cli/` are split.
- [`docs/threat-model.md`](docs/threat-model.md) — what Damping defends against, known bypass classes, fail-open vs. fail-closed.
- [`docs/cli-reference.md`](docs/cli-reference.md) — full command surface, hook contract, policy file schema.

## Repository map

| Path | What |
| --- | --- |
| `docs/architecture.md` | Monorepo layout, module naming, `ActionEvent`/`Decision` schema |
| `docs/cli-reference.md` | Full `damping` command surface, hook contract, policy file schema |
| `docs/threat-model.md` | What Damping defends against, known bypass classes, fail-open vs. fail-closed |
| `docs/ux-dashboard-spec.md` | Phase 4/5 team dashboard & enterprise compliance UI spec |
| `docs/調查資料/` | Enterprise infra research (Phase 3/4/5 self-hosted vs. vendor choices, Phase 6 spec) — three rounds, each verifying and adversarially stress-testing the last against primary sources |
| `features/` | Gherkin BDD scenarios — the acceptance criteria for every phase |
| `core/` | Transport-agnostic policy engine, schema, audit log — no dependency on any specific agent/transport |
| `cli/` | The `damping` binary: hook entrypoint, `mcp wrap`, `log`/`status`/`doctor`/`dashboard` subcommands |

## Building and testing

Requires Go 1.26+.

```
cd core && go build ./... && go test ./... -race -count=1
cd ../cli && go build ./... && go test ./... -race -count=1
```

Both modules build and test independently — `cli/go.mod` pins `core` via a `replace ../core` directive until `core` has a tagged release (a root `go.work` also exists for editor/IDE convenience). Before any commit, all of these should be clean, from both `core/` and `cli/`:

```
go build ./...
go vet ./...
gofmt -l .            # should print nothing
golangci-lint run ./...
gosec ./...
```

Run just the BDD suite on its own:

```
cd cli && go test ./bdd/... -v
```

A short local fuzz run on the shell parser (the one function that runs on fully untrusted input by design) is worth doing after touching `cli/shell`:

```
cd cli && go test ./shell/... -run=^$ -fuzz=FuzzAnalyze -fuzztime=30s
```

## Development methodology: BDD, scenario-first

This project's own governing rule is **情境通過才算完成** — "a scenario only counts as done once it passes." A feature isn't considered built until its Gherkin acceptance criteria are wired to real code and green — not the other way around (code first, tests added after, if at all).

The two halves:
- **`features/*.feature`** — Gherkin, one scenario per acceptance criterion, written in plain English before any implementation exists. Meant to be readable by someone who has never opened the Go source.
- **`cli/bdd/*_test.go`** — the real step-definition wiring, via [`cucumber/godog`](https://github.com/cucumber/godog), one file per feature file. Each file's `godog.TestSuite` runs from an ordinary `func TestFeatures_X(t *testing.T)`, so a plain `go test ./...` from `cli/` already executes every scenario as part of the normal test run — no separate suite to remember, no extra CI step.

Not every step is (or should be) a from-scratch runtime check. A step gets a **documented pass-through** instead of a second, weaker re-implementation when the behavior is already proven end-to-end by an equivalent, more thorough test elsewhere (e.g. MCP always-allow/deny session persistence is exercised by `cli/adapter/mcp/wrap_test.go`, not reinvented as Gherkin steps), or when the scenario describes a structural invariant that isn't independently observable from a single dynamic test run (e.g. "no adapter writes to the audit file directly"). Every such pass-through must carry an inline comment naming which real test covers it and why — an undocumented no-op step is a bug in the suite, not an accepted shortcut, since it silently stops proving the thing its own Gherkin wording claims to prove.

`@phase4`/`@phase5`-tagged scenarios (`team_dashboard.feature`, `compliance_report.feature`) describe features that don't exist yet — intentionally unwired, not broken.

### Adding or changing a policy rule

Every rule needs **both**:
1. A scenario in `features/dangerous_command.feature` (or `mcp_tool_governance.feature`) asserting it **blocks** a real dangerous case.
2. A scenario asserting it does **not** block a normal, safe case.

Add the matcher function in `core/policy/rules*.go`, register it in the `matchers` map, add the rule's metadata (including `risk:`, one of `low`/`medium`/`high`/`critical` — `Config.Validate()` rejects anything else) to `cli/policies/default.yaml`, and mirror both directions as Go tests. If the OPA/Rego engine is in scope for the change, keep `core/policy/policy.rego` in sync — `opa_equivalence_test.go` fails if the two engines ever diverge for the same input.

### Verifying a fix is real: mutation testing

For every behavioral bug fix, before considering it done: temporarily revert the fix, confirm the new or updated test now fails for the right reason, restore the fix, confirm green again. A test that can't fail this way isn't actually testing the fix.

## Implementation status (detail)

High-level status lives in README.md; this is the deeper per-package picture.

- **`core/`** — the transport-agnostic `ActionEvent` schema, the V1 policy engine (11 default rules, split across `rules_shell.go`/`rules_mcp.go`/`rules_selfprotection.go` by concern), always-allow/deny pattern matching (`patterns.go`) and persistence (`persist.go` — edits the policy YAML via `yaml.Node` surgery so comments and formatting elsewhere in the file survive), and the append-only JSONL audit log (`core/audit`, with rotation and crash-safe atomic writes via `core/atomicfile`).
- **`cli/`** — the `damping` binary: `init`, `doctor`, `status`, `on`/`off`, `log` (with `--channel`/`--risk`/`--actor`/`--outcome`/`--since`/`--limit` filters, a `tail -f`-style `--follow`, plus `log show <event_id>`), `policy list`/`test`/`validate`, `version`, and the real Claude Code `PreToolUse` hook entrypoint (`damping hook pretooluse`), including the `/dev/tty`-based confirmation flow with full allow-once/always-allow/deny-once/always-deny support (see `docs/architecture.md` §6 for why stdin/stdout can't be reused for that).
- **`damping mcp wrap -- <server-command>`** — the V1 thin MCP adapter (`cli/adapter/mcp`), a real client+server pair built on the official Go SDK: discovers the wrapped server's tools, re-exposes them unchanged, and runs every tool call through the exact same `core/policy` engine and `core/audit` log the CLI hook uses, before forwarding an allowed call to the real subprocess. No OAuth, no confused-deputy defense yet — that's Phase 3.
- **Shell danger detection** (`cli/shell`) — real `mvdan.cc/sh/v3` AST parsing (`parser.go`), Facts extraction (`facts.go`), and an explicit semantic layer for what AST parsing alone doesn't catch (`literal.go` + rule matchers): known aliases, base64/base32/uudecode/`xxd -r`/`openssl`-pipe-to-shell structural patterns, `/proc` sandbox-bypass path literals, dynamically-constructed command names, writes redirected into protected paths, and recursion into every command/process substitution (argument, redirect target, here-string) plus any heredoc body addressed to a real shell interpreter. `rm -rf` checks every path operand independently, not just the last word. See `docs/threat-model.md` §3.
- **BDD scenarios that actually run** — every V1-scope `features/*.feature` file executes for real via `godog` (`cli/bdd`): `dangerous_command.feature` (47 scenarios), `self_protection.feature`, `mcp_tool_governance.feature`, `audit_log.feature`, `policy_config.feature`, `local_dashboard.feature`.
- **OPA/Rego policy engine (Phase 3, partial)** — every rule above also has an embedded OPA/Rego implementation (`core/policy/policy.rego` + `opa.go`), selectable per-deployment via `policy.yaml`'s `engine: opa` field. `core/policy/opa_equivalence_test.go` proves both engines return byte-identical decisions for every rule; `opa_bench_test.go` gates eval latency at sub-millisecond.
- **`damping dashboard`** — a local, single-user web view of the audit log (`cli/dashboard`): summary strip, filterable event table, per-session risk sparklines, live tail via Server-Sent Events, no separate frontend build (vanilla JS + a Tailwind-compiled stylesheet checked into the repo, embedded via `go:embed`). Not Phase 4's team dashboard (`docs/ux-dashboard-spec.md`) — that's a separate, not-yet-built React+TS app.
- **Release engineering** (`.goreleaser.yaml`, `install.sh`, `.github/workflows/release.yml`) — cross-platform builds, a Homebrew cask, a one-line install script, all verified end-to-end locally.
- **Not yet built**: Phase 3's full Gateway (OAuth 2.1, confused-deputy defense), Phase 4's Cloudflare-based team dashboard, Phase 5's enterprise/compliance tier, Phase 6's memory-poisoning defense. See `docs/調查資料/` for infra research already done on Phases 3-6 (self-hosted vs. vendor tradeoffs, a concrete Phase 6 spec draft) — read round 3 first, it supersedes rounds 1-2's reversed calls.
- **Windows** — the `/dev/tty` interactive-prompt approach is Unix-only; `cli/ui/tty_windows.go` currently falls back to deny-by-default and documents the gap rather than faking support.

## CSS

If any UI work needs styling, use TailwindCSS — see `cli/dashboard/build/input.css` (compiled once via the standalone Tailwind CLI, checked into the repo, embedded via `go:embed`; regen instructions are in a comment at the top of that file).

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, ...). Explain *why* in the body, not just what — this project's history relies on commit messages carrying the actual rationale for a decision, not just a change summary.
