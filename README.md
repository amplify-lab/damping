# Damping

**One policy. One audit trail. Across your terminal and your MCP servers.**

Damping sits between your AI coding agent (Claude Code, Cursor, and more to come) and the real world. Before a destructive shell command or a risky MCP tool call actually runs, Damping checks it against a policy engine and gives you the chance to say no — and it writes down what happened either way, in one place, regardless of which channel the action came through.

```
⚠  Damping intercepted a destructive command

  Command: rm -rf ~/
  Rule:    destructive.rm_rf_protected
  Reason:  Recursive+force delete targeting a protected path — if this proceeds, this will delete your entire home directory or filesystem root

  [a] Allow once   [A] Always allow this exact command
  [d] Deny once    [D] Always deny this exact command
>
```

## Why not just use dcg, Aegis, or Pipelock?

Honestly, if all you want is "block `rm -rf`," [dcg](https://github.com/Dicklesworthstone/destructive_command_guard) is mature, popular, and works well — you should consider it. Damping's actual bet is different: **the same policy engine and the same audit log also cover your MCP tool calls**, not just your terminal. Run `damping log` after your agent trips a rule in either place and you'll see both events, in one trail, filterable by channel:

```
$ damping log --channel cli
$ damping log --channel mcp
```

Here's the honest breakdown against the closest tools in this space — we'd rather list where they win than pretend they don't (docs/00-統一開發計畫（定案版）.md §三 has the full research this table is drawn from):

| | Where it wins | What it doesn't do |
| --- | --- | --- |
| **[dcg](https://github.com/Dicklesworthstone/destructive_command_guard)** | 1,150+★, daily commits, 10+ agent integrations (Claude Code, Codex, Gemini CLI, Copilot CLI, Cursor, Grok, Aider), a much larger built-in rule set than Damping ships today | CLI-only — no MCP tool-call coverage, no cross-channel audit trail |
| **[Aegis](https://github.com/Justin0504/Aegis)** | The closest OSS project to "one policy + audit gateway," with a cryptographic audit trail and human-in-the-loop approval, plus SDK support across 9+ frameworks | A gateway/SDK deployment model built around a runtime mediation point, not a lightweight per-agent CLI+MCP hook — different operational shape, not a drop-in alternative for an individual developer's terminal |
| **[Pipelock](https://github.com/luckyPipewrench/pipelock)** | Purpose-built AI agent firewall for MCP/HTTP/A2A traffic — exfiltration, SSRF, and prompt-injection detection with signed action receipts | Answers "is data leaking out," not "what did this specific action do and who authorized it" — no fine-grained per-tool-call authorization or unified audit log |
| **Damping** | One policy engine and one audit trail across both your terminal and your MCP servers, at individual-developer scale, with real AST parsing (`mvdan/sh`) instead of regex, zero telemetry, and a single static Go binary | Newest of the four — smaller rule library than dcg's out of the box; no encrypted audit trail or gateway deployment mode (Aegis's strengths) |

Nobody else in this space unifies CLI and MCP under one engine and one audit trail at individual-developer scale — that's the actual differentiator, not the shell-blocking demo alone.

## Physics, briefly

*Damping* (阻尼), in physics, is the force that suppresses runaway oscillation and brings a system back to a stable range — it doesn't stop the system, it stabilizes it. That's the whole product philosophy: **governance isn't about blocking your AI agent. It's about damping its failure modes so it runs stably.** (Part of Amplify Lab's physics-themed product family — see `docs/品牌與命名體系.md`.)

## Quick start

```
brew install damping        # or: curl -sSL https://damping.dev/install | sh
damping init                # detects Claude Code / Cursor, installs the default policy, registers hooks
```

That's it — Damping runs invisibly until something dangerous happens, then it asks.

```
damping status              # is it on, which policy, which agents are wired up
damping doctor               # health check — hook registration, policy validity, degraded-mode history
damping log                  # replay everything it's intercepted, across every channel
damping policy test "rm -rf ~/"   # dry-run a command against your policy, no side effects
damping off --for 30m         # pause enforcement (the only sanctioned way to disable it — see docs/threat-model.md §4)
```

To cover your MCP servers too, point your MCP client config at Damping instead of the real server directly:

```
damping mcp wrap -- npx @some-org/example-mcp-server
```

Damping discovers the real server's tools, re-exposes them unchanged, and runs every call through the same policy engine and audit log as your terminal — before forwarding it on.

Full command reference: [`docs/cli-reference.md`](docs/cli-reference.md).

## What's real right now (V1 / Phase 1)

Everything below is implemented and covered by passing tests — not aspirational:

- **`core/`** — the transport-agnostic `ActionEvent` schema, the V1 policy engine (11 default rules, split across rules_shell.go/rules_mcp.go/rules_selfprotection.go by concern), always-allow/deny pattern matching (`patterns.go`) and **persistence** (`persist.go` — edits the policy YAML via `yaml.Node` surgery so comments and formatting elsewhere in the file survive), and the append-only JSONL audit log. `go test ./...` from `core/`.
- **`cli/`** — the `damping` binary: `init`, `doctor`, `status`, `on`/`off`, `log` (with `--channel`/`--risk`/`--actor`/`--outcome`/`--since`/`--limit` filters, a `tail -f`-style `--follow`, plus `log show <event_id>`), `policy list`/`test`/`validate`, `version`, and the real Claude Code `PreToolUse` hook entrypoint (`damping hook pretooluse`), including the exact `/dev/tty`-based confirmation flow with full **allow once / always allow / deny once / always deny** support (see `docs/architecture.md` §6 for why stdin/stdout can't be reused for that). `go test ./...` from `cli/`.
- **`damping mcp wrap -- <server-command>`** — the V1 thin MCP adapter (`cli/adapter/mcp`), a real client+server pair built on the official Go SDK: it discovers the wrapped server's tools, re-exposes them unchanged, and runs every tool call through the exact same `core/policy` engine and `core/audit` log the CLI hook uses, before forwarding an allowed call to the real subprocess. Verified end-to-end both with the SDK's in-memory test transports (`wrap_test.go`) and manually against real OS subprocesses (a real MCP client → `damping mcp wrap` → a real wrapped server, three separate processes). No OAuth, no confused-deputy defense — that's Phase 3. Always-allow/deny persistence works here too — an `[A]`/`[D]` choice is written into the policy file exactly like the CLI hook does, and an in-memory overlay makes it take effect for the rest of the same long-lived `mcp wrap` session immediately, not only on a future run (see `alwaysOverlay` in `cli/adapter/mcp/always_overlay.go`).
- **Shell danger detection** (`cli/shell`) — real `mvdan.cc/sh/v3` AST parsing (`parser.go`), Facts extraction (`facts.go`), and an explicit semantic layer for what AST parsing alone doesn't catch (`literal.go` + rule matchers): known aliases, base64-pipe-to-shell structural patterns, `/proc` sandbox-bypass path literals, dynamically-constructed command names, and writes redirected into protected paths. See `docs/threat-model.md` §3. `Analyze` — the one function that runs on fully untrusted, adversarially-crafted input by design — has native Go fuzz coverage (`fuzz_test.go`'s `FuzzAnalyze`, seeded from every real bypass this package's own tests assert on), run for 30s on every CI PR and for much longer locally; a crash there would crash the whole `damping hook pretooluse` subprocess, so this isn't optional hardening.
- **BDD scenarios that actually run** — every V1-scope `features/*.feature` file executes for real via `godog` (`cli/bdd`), not just as documentation: `dangerous_command.feature` (24 scenarios), `self_protection.feature`, `mcp_tool_governance.feature`, `audit_log.feature`, `policy_config.feature`, and `local_dashboard.feature`. Scenarios genuinely covered elsewhere by an equivalent, more thorough test (e.g. MCP always-allow/deny session persistence, already exercised end-to-end in `cli/adapter/mcp/wrap_test.go`) or describing a real design invariant that isn't independently checkable from a single dynamic test run (e.g. "no adapter writes to the audit file directly") get documented pass-through steps rather than a second, weaker re-implementation — see each `cli/bdd/*_test.go` file's doc comment for which and why. `features/compliance_report.feature` (@phase5) and `features/team_dashboard.feature` (@phase4) are feature-level-tagged for phases with no implementation yet, so they aren't wired at all.
- **OPA/Rego policy engine (Phase 3)** — every rule above also has an embedded OPA/Rego implementation (`core/policy/policy.rego` + `opa.go`), selectable per-deployment via `policy.yaml`'s `engine: opa` field instead of the Go-native default. `core/policy/opa_equivalence_test.go` proves both engines return byte-identical decisions for every rule; `opa_bench_test.go` gates eval latency at sub-millisecond. See `docs/architecture.md` §4.
- **`damping dashboard`** — a local, single-user web view of the same audit log `damping log` reads (`cli/dashboard`): dark-themed summary strip, a filterable event table (same `channel`/`risk`/`actor`/`outcome`/`since`/`limit` vocabulary as the CLI), a row-click detail view of the full event, per-session risk sparklines, and a live tail via Server-Sent Events — no separate frontend build (vanilla JS + a Tailwind-compiled stylesheet checked into the repo, embedded via `go:embed`). This is **not** Phase 4's team dashboard (`docs/ux-dashboard-spec.md`) — that's a separate, not-yet-built React+TS app needing a Cloudflare account and an SSO vendor decision; this one binds to `127.0.0.1` only, has no auth, and needs no infrastructure at all. See `docs/cli-reference.md` §9.1.
- **Release engineering** (`.goreleaser.yaml`, `install.sh`, `.github/workflows/release.yml`) — cross-platform builds (linux/darwin, amd64/arm64), a Homebrew formula, and the one-line install script this README's Quick Start already assumes, all verified end-to-end locally (`goreleaser release --snapshot --clean --skip=publish` produces working binaries; `install.sh` tested against a local fake release server). What's *not* live yet: an actual published GitHub Release, since that needs the real `amplify-lab` GitHub org and `damping.dev` domain, both still pending Tim's own confirmation/registration (see `docs/00-統一開發計畫（定案版）.md` "立即可執行的下一步" item 1) — the tooling is ready to activate the moment those land, not a guess at infrastructure that doesn't exist.

## What's designed but not yet built

Documented in detail (schema, CLI surface, UX copy) so implementing it is a matter of filling in code against an already-settled design, not re-deciding it:

- **Windows interactive prompt** — the `/dev/tty` approach is Unix-only; `cli/ui/tty_windows.go` currently falls back to deny-by-default and documents the gap rather than faking support.
- **Phase 3+**: the full MCPWarden Gateway (OAuth 2.1, confused-deputy defense — the OPA/Rego policy engine itself is already implemented, see above), the Cloudflare-based team dashboard, and the on-prem enterprise/compliance tier. See `docs/00-統一開發計畫（定案版）.md` §五 for the phased roadmap and `docs/ux-dashboard-spec.md` for that UI's design.

## Repository map

| Path | What |
| --- | --- |
| [`docs/00-統一開發計畫（定案版）.md`](docs/00-統一開發計畫（定案版）.md) | **Start here** — the current authoritative strategy + roadmap (Traditional Chinese; resolves conflicts across the earlier planning docs below) |
| [`docs/architecture.md`](docs/architecture.md) | Monorepo layout, module naming, `ActionEvent`/`Decision` schema |
| [`docs/cli-reference.md`](docs/cli-reference.md) | Full `damping` command surface, hook contract, policy file schema |
| [`docs/threat-model.md`](docs/threat-model.md) | What Damping defends against, known bypass classes, fail-open vs. fail-closed |
| [`docs/ux-dashboard-spec.md`](docs/ux-dashboard-spec.md) | Phase 4/5 team dashboard & enterprise compliance UI spec |
| [`features/`](features/) | Gherkin BDD scenarios — the acceptance criteria for every phase |
| `core/`, `cli/` | The Go modules described above |
| [`docs/市場調查與現況總覽.md`](docs/市場調查與現況總覽.md), [`docs/營運計劃書.md`](docs/營運計劃書.md), [`docs/總體開發藍圖-Fable5接手版.md`](docs/總體開發藍圖-Fable5接手版.md), [`docs/開發計畫.md`](docs/開發計畫.md), [`docs/品牌與命名體系.md`](docs/品牌與命名體系.md) | Historical planning record (market research, business plan, brand naming) — kept as provenance, superseded where they conflict with the doc above |

## How this project is developed: BDD, scenario-first

This project's own governing rule (from `docs/00-統一開發計畫（定案版）.md`'s closing line) is **情境通過才算完成** — "a scenario only counts as done once it passes." A feature isn't considered built until its Gherkin acceptance criteria are wired to real code and green — not the other way around (code first, tests added after, if at all).

The two halves:
- **`features/*.feature`** — Gherkin, one scenario per acceptance criterion, written in plain English before any implementation exists. Meant to be readable by someone who has never opened the Go source.
- **`cli/bdd/*_test.go`** — the real step-definition wiring, via [`cucumber/godog`](https://github.com/cucumber/godog), one file per feature file. This isn't a separate suite you have to remember to invoke: each file's `godog.TestSuite` runs from an ordinary `func TestFeatures_X(t *testing.T)`, so a plain `go test ./...` from `cli/` already executes every scenario as part of the normal test run — same pass/fail semantics as everything else, no extra CI step.

Run just the BDD suite on its own:
```
cd cli && go test ./bdd/... -v
```

Not every step is (or should be) a from-scratch runtime check. A step gets a **documented pass-through** instead of a second, weaker re-implementation when the behavior is already proven end-to-end by an equivalent, more thorough test elsewhere (e.g. MCP always-allow/deny session persistence is exercised by `cli/adapter/mcp/wrap_test.go`, not reinvented as Gherkin steps), or when the scenario describes a structural invariant that isn't independently observable from a single dynamic test run (e.g. "no adapter writes to the audit file directly"). Every such pass-through must carry an inline comment naming which real test covers it and why — an undocumented no-op step is a bug in the suite, not an accepted shortcut, since it silently stops proving the thing its own Gherkin wording claims to prove. If you find one without that comment, that's worth a bug report or a PR on its own.

`@phase4`/`@phase5`-tagged scenarios (`team_dashboard.feature`, `compliance_report.feature`) describe features that don't exist yet — intentionally unwired, not broken.

## Building from source

```
git clone https://github.com/amplify-lab/damping   # org name pending final confirmation — see docs/00-統一開發計畫（定案版）.md §二
cd damping
cd core && go build ./... && go test ./...
cd ../cli && go build ./... && go test ./...
```

Requires Go 1.26+. `go build`/`go test` work directly in each module without any extra workspace setup — `cli/go.mod` pins `core` via a `replace ../core` directive until `core` has a tagged release, per standard pre-release Go monorepo practice (a root `go.work` also exists for editor/IDE convenience).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The single most valuable contribution is a false positive report — a normal command Damping wrongly flagged — or a genuine bypass of a default rule. Both become permanent regression scenarios, never one-off fixes.

## Security

See [`SECURITY.md`](SECURITY.md) for how to report a vulnerability, including policy bypasses.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

---

*Damping is developed by [Amplify Lab](docs/品牌與命名體系.md), under 牧本科技股份有限公司 (Muben Technology Co., Ltd.), a Taiwan-registered entity — relevant to Damping's later enterprise/sovereign-governance tier, not to the individual/free tier above.*
