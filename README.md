# Damping

**One policy. One audit trail. Across your terminal and your MCP servers.**

Damping sits between your AI coding agent (Claude Code, Cursor, and more to come) and the real world. Before a destructive shell command or a risky MCP tool call actually runs, Damping checks it against a policy engine and gives you the chance to say no — and it writes down what happened either way, in one place, regardless of which channel the action came through.

```
⚠  Damping intercepted a destructive command

  Command: rm -rf ~/
  Risk:    critical — if this proceeds, this will delete your entire home directory
  Rule:    destructive.rm_rf_protected

  [a] Allow once   [A] Always allow this pattern
  [d] Deny once    [D] Always deny this pattern
>
```

## Why not just use [dcg](https://github.com/Dicklesworthstone/destructive_command_guard) or another shell guardrail?

Honestly, if all you want is "block `rm -rf`," dcg is mature, popular, and works well — you should consider it. Damping's actual bet is different: **the same policy engine and the same audit log also cover your MCP tool calls**, not just your terminal. Run `damping log` after your agent trips a rule in either place and you'll see both events, in one trail, filterable by channel:

```
$ damping log --channel cli
$ damping log --channel mcp
```

Nobody else in this space unifies both under one engine and one audit trail at individual-developer scale (see `docs/00-統一開發計畫（定案版）.md` §三 for the full competitive breakdown). We also default to zero telemetry, ship as a single static Go binary (no npm dependency tree), and use real AST parsing (`mvdan/sh`) instead of regex — but the cross-channel story is the actual differentiator, not the shell-blocking demo alone.

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

Full command reference: [`docs/cli-reference.md`](docs/cli-reference.md).

## What's real right now (V1 / Phase 1)

Everything below is implemented and covered by passing tests — not aspirational:

- **`core/`** — the transport-agnostic `ActionEvent` schema, the V1 policy engine (10 default rules), and the append-only JSONL audit log. `go test ./...` from `core/`.
- **`cli/`** — the `damping` binary: `init`, `doctor`, `status`, `on`/`off`, `log` (with `--channel`/`--risk`/`--actor`/`--outcome`/`--since` filters), `policy list`/`test`/`validate`, and the real Claude Code `PreToolUse` hook entrypoint (`damping hook pretooluse`), including the exact `/dev/tty`-based confirmation flow (see `docs/architecture.md` §6 for why stdin/stdout can't be reused for that). `go test ./...` from `cli/`.
- **Shell danger detection** (`cli/shell`) — real `mvdan.cc/sh/v3` AST parsing, plus an explicit semantic layer for what AST parsing alone doesn't catch: known aliases, base64-pipe-to-shell structural patterns, `/proc` sandbox-bypass path literals, and dynamically-constructed command names. See `docs/threat-model.md` §3.
- **BDD scenarios that actually run** — `features/dangerous_command.feature`'s 20 scenarios execute for real via `godog` (`cli/bdd`), not just as documentation. The remaining `features/*.feature` files have equivalent behavior covered as plain Go tests in `cli/cmd`, `core/policy`, and `core/audit`.

## What's designed but not yet built

Documented in detail (schema, CLI surface, UX copy) so implementing it is a matter of filling in code against an already-settled design, not re-deciding it:

- **`damping mcp wrap`** — the V1 thin MCP client-side adapter (policy + audit only, no OAuth). Fully specified in `docs/architecture.md` §7 and `docs/cli-reference.md` §9; not yet implemented.
- **Always-allow / always-deny pattern persistence** (writing the user's `[A]`/`[D]` prompt choice back into the policy file) — V1's prompter currently supports allow-once/deny-once only (`cli/ui`).
- **Windows interactive prompt** — the `/dev/tty` approach is Unix-only; `cli/cmd/tty_windows.go` currently falls back to deny-by-default and documents the gap rather than faking support.
- **Phase 3+**: the full MCPWarden Gateway (OAuth 2.1, confused-deputy defense, OPA/Rego), the Cloudflare-based team dashboard, and the on-prem enterprise/compliance tier. See `docs/00-統一開發計畫（定案版）.md` §五 for the phased roadmap and `docs/ux-dashboard-spec.md` for that UI's design.

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
