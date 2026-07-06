# Damping

**One policy. One audit trail. Across your terminal and your MCP servers.**

Damping sits between your AI coding agent (Claude Code, Cursor, and more to come) and the real world. Before a destructive shell command or a risky MCP tool call actually runs, Damping checks it against a policy engine and gives you the chance to say no — and it writes down what happened either way, in one place, regardless of which channel the action came through.

```
⚠  Damping intercepted a destructive command

  Command: rm -rf ~/
  Rule:    destructive.rm_rf_protected
  Reason:  Recursive+force delete of a path that isn't a known regenerable build/cache directory (node_modules, dist, build, ...) — for your home directory, filesystem root, or a configured protected path, this could destroy irreplaceable data

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

*Damping* (阻尼), in physics, is the force that suppresses runaway oscillation and brings a system back to a stable range — it doesn't stop the system, it stabilizes it. That's the whole product philosophy: **governance isn't about blocking your AI agent. It's about damping its failure modes so it runs stably.** (Part of Amplify Lab's physics-themed product family.)

## Quick start

### 1. Install and set up

```
brew install damping        # or: curl -sSL https://damping.dev/install | sh
damping init                # detects Claude Code / Cursor, installs the default policy, registers hooks
```

`damping init` prints a confirmation for every agent it found and wired up, and closes with a one-line demo suggestion (`ask your agent to run rm -rf /tmp/test`) — that's step 2 below.

### 2. Watch it intercept something

Ask your agent (Claude Code, Cursor) to run something Damping's default policy treats as destructive — `rm -rf /tmp/test` is the safe way to see this without risking real data. You'll see this at your terminal, not in the agent's own chat window (Damping owns its own confirmation prompt on `/dev/tty`, independent of whichever agent triggered it):

```
⚠  Damping intercepted a destructive command

  Command: rm -rf ~/
  Rule:    destructive.rm_rf_protected
  Reason:  Recursive+force delete of a path that isn't a known regenerable build/cache directory (node_modules, dist, build, ...) — for your home directory, filesystem root, or a configured protected path, this could destroy irreplaceable data

  [a] Allow once   [A] Always allow this exact command
  [d] Deny once    [D] Always deny this exact command
>
```

- **`a`** / **`d`** decide just this one call.
- **`A`** / **`D`** persist the decision (an exact-match pattern written into your policy file) so the same command never prompts again — useful once you've confirmed a repeated command in your workflow (e.g. `rm -rf ./dist/*` in a build script) is actually fine.

### 3. Review what happened

Every action Damping evaluates — allowed, prompted, or denied, on either channel — lands in one audit trail:

```
damping log                        # replay everything it's intercepted, across every channel
damping log --risk critical        # just the critical-severity events
damping log --channel mcp --since 24h
damping log --follow               # tail -f style, live
```

Or open the same log in a local, zero-setup web view:

```
damping dashboard                  # binds to 127.0.0.1:4243 by default
```

<img src="docs/assets/dashboard-demo.png" alt="damping dashboard showing a filterable event table with per-session risk sparklines, mixing CLI and MCP channel events across all four risk tiers" width="700">

*(Real output from a seeded local audit log — not a mockup. Rows span both channels, all four risk tiers, both allow/deny/prompt outcomes, and two different agents, which is the whole point: one table, not one per tool.)*

### 4. Cover your MCP servers too

Point your MCP client config at Damping instead of the real server directly:

```
damping mcp wrap -- npx @some-org/example-mcp-server
```

Damping discovers the real server's tools, re-exposes them unchanged, and runs every call through the exact same policy engine and audit log as your terminal — before forwarding it on. Nothing about the wrapped server's behavior changes from the client's point of view except that a destructive tool call can now be intercepted, exactly like a shell command.

### 5. Everyday commands

```
damping status                     # is it on, which policy, which agents are wired up
damping doctor                     # health check — hook registration, policy validity, degraded-mode history
damping policy test "rm -rf ~/"     # dry-run a command against your policy, no side effects
damping off --for 30m               # pause enforcement (the only sanctioned way to disable it — see docs/threat-model.md §4)
```

Full command reference: [`docs/cli-reference.md`](docs/cli-reference.md).

## What's real right now (V1 / Phase 1)

Everything below is implemented and covered by passing tests — not aspirational:

- CLI shell-command interception, with real AST parsing (not regex), across 11 default rules (destructive deletes, force pushes, destructive SQL, recursive permission changes, unvetted install pipelines, encoded payloads, sandbox-bypass paths, and more) — see `docs/threat-model.md` for the full list and known bypass classes.
- `damping mcp wrap` — the same policy engine and audit log, for MCP tool calls too, not just your terminal.
- A local `damping dashboard` (screenshot above) and `damping log` for replaying the full audit trail across both channels.
- An embedded OPA/Rego policy engine as a selectable alternative to the default Go-native one.
- 90 BDD (Gherkin) scenarios, all wired to real code and passing, not just documentation.
- Cross-platform release engineering (Homebrew, one-line install script, GitHub Releases for linux/darwin × amd64/arm64).

Not yet built: Phase 3's full enterprise Gateway (OAuth 2.1, confused-deputy defense), Phase 4's Cloudflare-based team dashboard, Phase 5's enterprise/compliance tier. Engineering-level detail on everything above lives in [`CLAUDE.md`](CLAUDE.md), not here.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to contribute, or [`CLAUDE.md`](CLAUDE.md) for the full engineering conventions and repository map. The single most valuable contribution is a false positive report — a normal command Damping wrongly flagged — or a genuine bypass of a default rule. Both become permanent regression scenarios, never one-off fixes.

## Security

See [`SECURITY.md`](SECURITY.md) for how to report a vulnerability, including policy bypasses.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

---

*Damping is developed by Amplify Lab, under 牧本科技股份有限公司 (Muben Technology Co., Ltd.), a Taiwan-registered entity — relevant to Damping's later enterprise/sovereign-governance tier, not to the individual/free tier above.*
