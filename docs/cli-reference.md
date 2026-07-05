# Damping — CLI Reference

> Full command surface for the `damping` binary. This is the contract the `cli/cmd` package (Cobra) implements against — every subcommand listed here should exist as a stub (even if not fully wired) by the end of Phase 0, per `docs/00-統一開發計畫（定案版）.md` §五 Phase 1. All user-facing strings are English — the product's audience is global individual developers (Show HN / Product Hunt), even though internal planning docs are Traditional Chinese for Tim's team.

## 1. Command tree

| Command | Phase | Purpose |
| --- | --- | --- |
| `damping init` | 1 | Detect installed agents (Claude Code, Cursor), write hook config, install default policy |
| `damping doctor` | 1 | Environment/health check — hook registration, policy validity, degraded-mode history |
| `damping status` | 1 | One-line current state: enabled/disabled, active policy, detected integrations |
| `damping on` / `damping off` | 1 | Enable / temporarily disable enforcement |
| `damping log` | 1 | Replay the local audit trail |
| `damping dashboard` | 1 (not in the original plan — see §9.1) | Serve a local, read-only web view of the same audit trail `damping log` reads |
| `damping policy list` / `test` / `edit` / `validate` | 1 | Inspect and dry-run the policy file |
| `damping mcp wrap -- <server-command>` | 1 | V1 thin MCP stdio wrapper (policy + audit only, no OAuth) — **implemented**, see §9 |
| `damping hook <event>` | 1 | Internal entrypoint invoked by agent hook configs — not meant for direct interactive use |
| `damping sync enable` / `disable` | 4 | Team tier opt-in cloud sync (not implemented until Phase 4) |
| `damping completion <shell>` | 1 | Shell completion script (bash/zsh/fish/powershell) — provided automatically by Cobra |
| `damping version` | 1 | Print version + build info |
| `damping upgrade` | 2+ | Self-update (documented now, implemented post-launch) |

Global flag on every command: `--config <path>` (default `~/.damping/policy.yaml`, or `$DAMPING_HOME/policy.yaml`). `--json` is `log`-specific, not global (see §7) — there is no global `--json` or `-v/--verbose` flag in V1; don't assume one.

## 2. Exit codes (the CLI binary itself — distinct from the hook contract in §6)

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | General error — **including bad flags/unknown subcommands**: Cobra's own arg/flag validation errors are plain errors with no special exit code, so they fall through to this one (verified directly: `damping log --bogus-flag` and `damping nonexistent-subcommand` both exit 1, not 2) |
| 2 | `damping hook pretooluse` only — a hard deny (see §11). Not a general "usage error" code despite an earlier draft of this table claiming that; nothing else in the CLI produces exit 2 |
| 3 | `damping policy test` — the tested command was flagged (verdict `deny` or `prompt`, i.e. anything but a plain `allow` — see §8) |
| 4 | `damping doctor` — one or more checks failed; also `damping status` when enforcement is ON but the policy file failed to load (headline reads "NOT protecting you", see §5 — `damping off` always exits 0 regardless of policy validity, since OFF is already the stronger signal) |

## 3. `damping init`

```
$ damping init
Damping v0.1.0 — one-time setup

  → Installed default policy to ~/.damping/policy.yaml
  ✓ Detected Claude Code (~/.claude/settings.json)
  → Registered PreToolUse hook in Claude Code settings
  ✓ Detected Cursor (~/.cursor/hooks.json)
  → Registered beforeShellExecution hook in Cursor

✓ Setup complete — try it: ask your agent to run `rm -rf /tmp/test`

Run `damping doctor` any time to re-verify this setup.
```

Flags: `--agent claude-code|cursor|all` (default `all`, only touches detected agents), `--force` (overwrite existing policy/hook entries — this is the one flag that controls both, not hook entries alone), `--dry-run` (print what would change, write nothing; the closing line becomes "Setup complete (dry run) —" with no demo call-to-action, since nothing was actually installed to try).

Target: install → first interception demo in under 3 minutes (per the original plan's UX bar).

## 4. `damping doctor`

Read-only, idempotent, safe to run anytime — the diagnostic pattern research confirmed across `brew doctor`/`flutter doctor`/`gh`.

```
$ damping doctor
Damping doctor — environment check

  ✓ Policy file valid (~/.damping/policy.yaml, 11 rules)
  ✓ Claude Code hook registered
  ✗ Cursor hook missing — was it removed outside `damping off`?
      → run `damping init --agent cursor --force` to reinstall
  ⚠ 2 degraded-mode event(s) in the last 7 days — run `damping log --outcome degraded` for details

1 check(s) failed, 1 warning(s).
```

Exit code 4 if any check fails. An agent whose hook was never registered at all (never ran `damping init`, or that agent isn't installed) shows an informational `·` line ("not registered — run `damping init`") rather than either ✓ or ✗ — only an agent that **was** previously seen registered and has since disappeared is treated as a failure (see `docs/threat-model.md` §4's self-protection requirement). `--verbose`/paste-ready bundle and `--json` output described in earlier drafts of this doc are **not implemented in V1** — `damping doctor` takes no flags today.

The "hook missing since last check" case is the direct, user-visible surface of the self-protection requirement in `docs/threat-model.md` §4 — it must never be silently absent from this output.

A fourth check line this section previously omitted: `damping doctor` also hashes the active policy file (SHA-256) and remembers it between runs; if the hash differs from what was recorded last time, it prints `⚠ Policy file hash changed since the last check (<path>)` in place of the `✓ Policy file valid` line, and counts as a warning — see `docs/threat-model.md` §8's tamper-evidence discussion. Like the hook-missing case, this needs at least two runs to fire (the first run establishes the baseline hash with no way to know if it's already been tampered with).

## 5. `damping status`

```
$ damping status
Damping: ON
Policy:  ~/.damping/policy.yaml (11 rules)
Agents:  claude-code (active), cursor (active)
Sync:    disabled (individual tier)
```

If the policy file can't be loaded (missing, unreadable, or invalid YAML), the headline itself warns instead of a bare "ON" — the "ON" bit only ever meant "not explicitly `damping off`'d", entirely independent of whether the policy it's supposed to enforce can actually be read:

```
$ damping status
Damping: ON, but NOT protecting you — the policy file failed to load, so every CLI shell-command action fails open (see Policy line below; `damping mcp wrap` instead refuses to start at all on this same error)
Policy:  ~/.damping/policy.yaml (error: policy: reading ~/.damping/policy.yaml: open ~/.damping/policy.yaml: no such file or directory)
Agents:  claude-code (active), cursor (active)
Sync:    disabled (individual tier)
```

Exit code 4 in that case (see §2) — the same code `damping doctor` already uses for the identical underlying failure, so a script chaining `damping status && deploy` gets a real signal instead of silently continuing past a loud warning nobody parses stdout for.

## 6. `damping on` / `damping off`

```
$ damping off
⚠  Damping enforcement is now OFF. Your agent's commands will NOT be checked.
    This was a manual, explicit action — logged as self_disable at 2026-07-05T10:03:00+08:00.
    Run `damping on` to re-enable.

$ damping off --for 30m
⚠  Damping enforcement paused for 30m (until 10:33PM), then auto re-enables.

$ damping on
✓ Damping enforcement is back ON.
```

`damping on` also re-checks whether the policy file it just re-enabled can actually load, warning right there if not — the one moment a user is most likely to trust "back ON" means "protected" without separately re-checking `damping status`:

```
$ damping on
✓ Damping enforcement is back ON.
⚠  But NOT protecting you — the policy file failed to load: policy: reading ~/.damping/policy.yaml: open ~/.damping/policy.yaml: no such file or directory
```

`damping off` is the **only** sanctioned disable path (see `docs/threat-model.md` §4) — it is a deliberate human action at a terminal, not something reachable through a Bash tool call an agent would plausibly be instructed to run. `--for <duration>` avoids the "I forgot it was off" failure mode research flagged as a real churn risk (users disabling permanently out of launch-week frustration).

## 7. `damping log`

```
$ damping log --channel mcp --risk high --since 24h
TIME                 CHANNEL ACTOR          TARGET                         RISK     DECISION
2026-07-05 09:41:02  mcp     claude-code    filesystem.delete_all          high     deny

$ damping log --json | head -1 | jq .
{"event_id":"evt_...", "channel":"mcp", "action_type":"tool_call", "decision":{"verdict":"prompt","resolved_verdict":"deny",...}, ...}

$ damping log show evt_a1b2c3d4
# pretty-printed full ActionEvent for one event_id — raw command/call, parsed args, policy_id, decision (including resolved_verdict if it was a resolved Prompt)
```

Filters: `--channel cli|mcp`, `--risk low|medium|high|critical`, `--since <duration>`, `--actor <name>`, `--outcome allow|deny|prompt|degraded`, `--limit N` (most-recent N events). Default output is a human-readable table (the `DECISION` column shows `Decision.Outcome()` — the resolved verdict, not the raw pre-prompt one — with ` (degraded)` appended for an internal-failure record, since `Degraded` is a separate flag from the verdict and would otherwise look identical to a genuine policy allow in this view); `--json` outputs newline-delimited JSON (NDJSON — one object per line, not a JSON array; pipe through `jq -s` to slurp into an array, or `head -1 | jq .` for one record) for scripting/SIEM ingestion. Empty results print `No audit events matched those filters.` — never a blank screen in plain mode. In `--json` mode that same notice goes to **stderr**, not stdout, so stdout is genuinely empty (zero lines) rather than one non-JSON line — the same stdout-purity rule `--follow` follows, below.

`--follow` keeps `damping log` running after printing the existing matches, printing each new matching event as it's appended (`tail -f`, not `tail -F`) — Ctrl+C to stop. It polls the file rather than using a filesystem-event API (`core/audit.Follow`), so it stays dependency-free and portable, and recovers correctly if `Rotate` renames the file away mid-session. The "Watching for new events..." notice goes to **stderr**, not stdout, specifically so `damping log --follow --json | jq -c .` (or any other NDJSON consumer) sees a clean, uninterrupted JSON stream on stdout — found via manually testing the actual pipe, not just unit tests.

Filtering by `--channel` is also the concrete, in-product demonstration of the cross-channel unification claim in the master plan — this is where a skeptical reviewer sees "one log, two channels" for themselves.

## 8. `damping policy`

```
$ damping policy list
ID                                         RISK      ACTION
destructive.rm_rf_protected                critical  prompt
destructive.git_push_force                 high      prompt
destructive.sql_drop_truncate              high      prompt
destructive.chmod_777_recursive            medium    prompt
destructive.curl_pipe_sh_unallowlisted     medium    prompt
destructive.encoded_payload_pipe           high      prompt
destructive.proc_sandbox_bypass            critical  deny
destructive.dynamic_command_construction   medium    prompt
destructive.write_protected_path           critical  prompt
mcp.destructive_tool_call                  high      prompt
self_protection.damping_off_attempt        critical  deny

$ damping policy test "rm -rf ~/Documents"
→ Would PROMPT (rule: destructive.rm_rf_protected, reason: Recursive+force delete targeting a protected path — if this proceeds, this will delete your entire home directory or filesystem root)

$ damping policy edit     # opens $EDITOR on ~/.damping/policy.yaml
$ damping policy validate # schema + rule sanity check, no side effects
```

`damping policy test`'s output is a single line — `decision.Decision` has no `risk` field to print separately (only `Verdict`/`ResolvedVerdict`/`PolicyID`/`Reason`/`Degraded`), so the matched rule's reason is folded into the same parenthetical as the rule id, not shown on its own indented `Reason:` line as an earlier draft of this doc showed.

`damping policy test` exits `3` when the verdict is anything other than a plain `allow` (i.e. `deny` OR `prompt` — "was this flagged at all" is the useful CI assertion, not just "was it hard-denied"), `0` when the verdict is `allow`. This is what makes it usable as a CI gate: run it over a corpus of known-dangerous commands (expect exit 3) and known-safe commands (expect exit 0), per the "must-never-block regression list" testing discipline.

## 9. `damping mcp wrap` (V1 thin adapter — see `docs/architecture.md` §7)

```
$ damping mcp wrap -- npx @some-org/example-mcp-server
```

Configured as the launch command in place of the real server inside Claude Code's / Cursor's MCP server config. Damping spawns the real server as a subprocess, speaks MCP over stdio to the actual client, and for every outgoing tool call: normalizes it into an `ActionEvent` (`channel: mcp`), runs it through `core/policy`, writes it to `core/audit`, then forwards the (possibly user-confirmed) call through to the real subprocess. No OAuth, no token re-issuance — that's Phase 3's `gateway/` (see architecture.md §7).

## 9.1 `damping dashboard`

```
$ damping dashboard
Dashboard running at http://127.0.0.1:4243 (Ctrl+C to stop)
```

A small local HTTP server rendering the same `~/.damping/audit.jsonl` `damping log` reads, in a browser — a dark-themed summary strip, a filterable event table, a per-session risk sparkline panel, a live tail via Server-Sent Events, and a row-click detail view (the full `ActionEvent`: raw command/call, parsed args, matched policy_id, and the resolution timeline for a resolved prompt — the same fields `damping log show <event_id>` prints), all served from `cli/dashboard` with no separate frontend build (vanilla JS, a Tailwind-compiled stylesheet checked into the repo and embedded via `go:embed`).

**This is not Phase 4.** `docs/ux-dashboard-spec.md` describes a separate, not-yet-built team dashboard — React+TS, Cloudflare-hosted, SSO auth, cross-member team sync — genuinely blocked on Tim picking a Cloudflare account and an auth vendor. `damping dashboard` needs none of that: no auth, no network calls beyond serving its own page, binds to `127.0.0.1` only by default. It borrows that spec's visual language (dark theme, risk-as-temperature color, the damped-oscillation sparkline motif) and its "CLI/dashboard vocabulary parity" principle (§4 of that spec) — the same `core/audit.ParseFilter` that parses `damping log --risk critical` also parses `?risk=critical` on `/api/events`.

Flags: `--port` (default `4243`), `--host` (default `127.0.0.1` — passing anything else prints an explicit warning that the audit log becomes reachable, unauthenticated, from wherever that address is reachable). Routes: `GET /` (the page), `GET /static/dashboard.css` (the compiled stylesheet), `GET /api/summary`, `GET /api/sessions`, `GET /api/events` (same filters as `damping log`: `channel`, `risk`, `actor`, `outcome`, `since`, `limit`), `GET /api/events/stream` (Server-Sent Events, same filters minus `limit` — a live tail has no "most recent N" to cap, built on the same `core/audit.Follow` poll `damping log --follow` uses).

`/api/events`'s `limit` differs from `damping log --limit` in one respect: the CLI's own default is `0` (unbounded — a terminal user can scroll or pipe), but this endpoint defaults to 200 when `limit` is omitted entirely, since its response gets re-rendered as DOM rows in a live browser tab on every filter change rather than streamed to a pager. An explicit `?limit=0` still means unlimited, matching the CLI's vocabulary exactly. Whenever the default (or an explicit) limit actually drops events, the response carries an `X-Damping-Truncated: true` header and the page shows a small inline note — per `docs/ux-dashboard-spec.md` §4's "never silently drop data," even a sane default shouldn't trim history without saying so.

While bound to the default `127.0.0.1`, every request's `Host` header is checked against `127.0.0.1`/`localhost` and rejected (403) otherwise — binding to localhost alone does not stop a malicious webpage from reading this unauthenticated server via DNS rebinding (resolving an attacker-controlled domain to `127.0.0.1` mid-session, then treating the connection as same-origin with that domain), and a rebound request still carries the attacker's domain as its `Host`. This check steps aside once `--host` is explicitly set to anything else, since there's no longer one correct value to allowlist — that's the moment the startup warning above already exists for.

## 10. `damping hook <event>`

```
$ damping hook pretooluse   # reads JSON on stdin, responds via exit code per §11
```

Not meant for interactive use — this is the entrypoint `damping init` wires into the agent's hook config. Documented here because a curious user inspecting `~/.claude/settings.json` will see it referenced and should be able to find out what it does.

## 11. Hook contract (Claude Code / Cursor) — exact wire format

Verified against official docs during planning (see `docs/00-統一開發計畫（定案版）.md` §四 修正二 for the correction this made to earlier drafts):

**Claude Code** (`~/.claude/settings.json` → `hooks.PreToolUse[]`, `matcher: "Bash"`):
- stdin JSON includes `session_id`, `cwd`, `hook_event_name: "PreToolUse"`, `tool_name: "Bash"`, `tool_input.command`.
- **Exit code `2`** = hard deny (tool call cancelled, stderr fed back to the model as the reason).
- **Exit code `0`** + stdout JSON `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"|"deny"|"ask","permissionDecisionReason":"..."}}` is the documented general contract, and `"ask"` is how a hook can defer to Claude Code's own native permission UI. **Damping's V1 hook does not use this path** — its stdin/stdout are already spoken-for by this same JSON protocol, so it cannot simultaneously run its own branded interactive prompt (§12) over the same streams. Instead it opens the controlling terminal directly (`/dev/tty`), resolves a `Prompt`-tier decision fully itself, and only then responds with a plain exit code — see `docs/architecture.md` §6.
- Any other exit code (1, 3, ...) is **non-blocking** — the command still runs, only the first stderr line is shown. Damping's hook entrypoint must never rely on this path for a deny.

**Cursor** (`.cursor/hooks.json` or `~/.cursor/hooks.json`, `beforeShellExecution` / `beforeMCPExecution` / etc.):
- stdin JSON: `{command, cwd, sandbox, ...}`.
- Returns `{"permission": "allow"|"deny"|"ask", "user_message": "...", "agent_message": "..."}`.
- Exit code `2` blocks; other non-zero codes **fail open** by default unless the hook config sets `failClosed: true`.

Both agents fail open on anything other than the documented deny path — this is an external constraint Damping does not control (see `docs/threat-model.md` §6).

## 12. Confirmation prompt — exact UX copy

**Note on this section's history**: an earlier draft of this doc specced a richer prompt (separate `Agent:`/`Channel:`/`Risk:` lines, a distinct MCP-specific template with `Server:`/`Tool:`/`Args:`, and `[v]`/`[?]` drill-down options). The actual shipped implementation (`cli/ui/prompt.go`'s `TTYPrompter.Confirm`) is simpler and — found via a manual UX walkthrough of the real binary — was never updated to match back into this doc. This section now documents what's actually implemented, not the original aspiration:

- **One shared template** for both channels, not two — the same `Confirm` call renders a CLI shell command and an MCP tool call identically; `Command:` shows whatever raw text the caller passed in (the shell command text for a hook interception, or `<tool name> <json args>` for an MCP call — see `cli/adapter/mcp/facts.go`'s `rawCallSummary`).
- **No separate `Agent:`/`Channel:`/`Risk:` lines** — `Confirm(raw string, d decision.Decision) Resolution` doesn't receive that context at all today.
- **`Reason:` instead of a `[?] Why is this flagged?` drill-down** — the matched rule's description is shown inline unconditionally, which is what the original `[?]` option would have surfaced on request anyway.
- **No `[v] View full command` option** — the full `Command:` text is already shown inline, unredacted, with no truncation, so there's nothing left to drill into.

Shell command interception:

```
⚠  Damping intercepted a destructive command

  Command: rm -rf ~/
  Rule:    destructive.rm_rf_protected
  Reason:  Recursive+force delete targeting a protected path — if this proceeds, this will delete your entire home directory or filesystem root

  [a] Allow once   [A] Always allow this exact command
  [d] Deny once    [D] Always deny this exact command
>
```

MCP tool-call interception — the exact same template and wording (still "exact command", not "exact call" — the prompt has no channel-specific branching):

```
⚠  Damping intercepted a destructive command

  Command: filesystem.delete_all {"path":"/data"}
  Rule:    mcp.destructive_tool_call
  Reason:  MCP tool the server itself declared destructive (ToolAnnotations.DestructiveHint)

  [a] Allow once   [A] Always allow this exact command
  [d] Deny once    [D] Always deny this exact command
>
```

`[A]`/`[D]` persist the **exact command text** into `always_allow`/`always_deny` (via `core/policy.AppendAlwaysPattern`, which edits the policy YAML through `yaml.Node` surgery rather than a full round trip, so comments and formatting elsewhere in the file survive). The underlying matcher (`core/policy/rules.go`'s `matchGlobPattern`) also supports a trailing `*` as a prefix wildcard for hand-authored rules (e.g. `git status*` typed directly into the policy file) — but V1's automatic `[A]`/`[D]` persistence does not auto-generalize into a glob on its own; it remembers only the one exact command you approved. Deny always overrides allow when both a always-allow and always-deny pattern could match (defense-in-depth: an accidental broad allow can't silently swallow a narrower, more specific deny) — see `core/policy.Engine.Evaluate`, which checks `always_deny` before `always_allow`.

## 13. Policy file schema (`~/.damping/policy.yaml`, installed by `damping init`)

The block below is kept identical to the actual shipped file at `cli/policies/default.yaml` (embedded into the binary via `go:embed` — see `docs/architecture.md` §1 for why the canonical copy lives under `cli/` rather than a repo-root `policies/`). `protected_paths` and `always_allow`/`always_deny` are matched by exact value or `/`-prefix only in V1 (see `core/policy/rules.go`'s `inProtectedPaths` and `matchGlobPattern`, which supports a single trailing `*` as a prefix wildcard) — no `**` or mid-string glob syntax is implemented yet, so don't rely on it in a hand-edited policy file.

An optional top-level `engine` field (`native` — the default, if omitted — or `opa`) selects which `policy.Evaluator` implementation evaluates every rule below: `native` is the hardcoded Go matcher registry, `opa` is the embedded OPA/Rego engine introduced in Phase 3. Both produce identical decisions for every rule id here — see `docs/architecture.md` §4.

```yaml
# engine: native
version: 1

protected_paths:
  - ~/.ssh
  - ~/.aws
  - .env
  - .env.production

allowlisted_install_domains:
  - damping.dev
  - raw.githubusercontent.com

rules:
  - id: destructive.rm_rf_protected
    description: Recursive+force delete targeting a protected path — if this proceeds, this will delete your entire home directory or filesystem root
    risk: critical
    action: prompt
  - id: destructive.git_push_force
    description: Force-push can overwrite remote history
    risk: high
    action: prompt
  - id: destructive.sql_drop_truncate
    description: DROP TABLE / TRUNCATE issued via a shell-invoked DB client
    risk: high
    action: prompt
  - id: destructive.chmod_777_recursive
    description: Recursive world-writable permissions
    risk: medium
    action: prompt
  - id: destructive.curl_pipe_sh_unallowlisted
    description: curl|sh or wget|sh from a domain not in allowlisted_install_domains
    risk: medium
    action: prompt
  - id: destructive.encoded_payload_pipe
    description: base64-decode (or similar) piped into a shell/eval
    risk: high
    action: prompt
  - id: destructive.proc_sandbox_bypass
    description: Known /proc-based sandbox bypass path literals
    risk: critical
    action: deny
  - id: destructive.dynamic_command_construction
    description: Command name built dynamically (e.g. command substitution) and cannot be statically resolved
    risk: medium
    action: prompt
  - id: destructive.write_protected_path
    description: Output redirected (>, >>, etc) into a protected path
    risk: critical
    action: prompt
  - id: mcp.destructive_tool_call
    description: MCP tool the server itself declared destructive (ToolAnnotations.DestructiveHint)
    risk: high
    action: prompt
  - id: self_protection.damping_off_attempt
    description: Agent tried to run "damping off" itself via its own Bash tool call (the Ona-incident failure mode)
    risk: critical
    action: deny

# mcp.write_tool_unscoped_identity is implemented (core/policy/rules.go) but
# deliberately NOT listed here — see the note in the shipped
# cli/policies/default.yaml for why: no identity system exists at the
# individual tier, so this rule would nag on nearly every MCP tool call.

# Populated at runtime by the TTY prompt's "always allow/deny" choice — not hand-edited normally.
always_allow: []
always_deny: []
```

Full rule-matching grammar (command/flags/args/pipeline shape matchers) lives in code as `core/policy` matures past the initial hardcoded V1 rule set — this file is the **behavioral** contract (what ships, what risk tier, what default action), not the internal matcher DSL, which is free to evolve as long as `damping policy test` output stays stable.
