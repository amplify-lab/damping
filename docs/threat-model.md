# Damping — Threat Model

> Phase 0.3 deliverable referenced by the original engineering plan but never written until now. This document doubles as the skeleton for the public-facing security whitepaper — write it assuming an external security researcher or a skeptical HN commenter is the reader, not just internal engineering.

## 1. What Damping protects against

Damping sits between an AI coding agent (Claude Code, Cursor, and future integrations) and the real world — the shell it executes commands in, and the MCP servers it calls tools on. The threat model is scoped to **actions with real-world side effects that the agent initiates**, not to the agent's reasoning quality or hallucination rate. Damping does not try to make the agent smarter; it tries to make sure a bad decision (the agent's own, or one it was manipulated into) doesn't execute unchecked.

Grounding incidents (real, not hypothetical — see `docs/00-統一開發計畫（定案版）.md` and `市場調查與現況總覽.md` §17 for sources):
- A Replit agent deleted a production database affecting 1,200+ executives at a customer company.
- A Cursor agent deleted 70 files after being told explicitly not to execute anything.
- A Claude Code `rm -rf` wiped a user's entire home directory.
- A sandboxed agent bypassed a blacklist via `/proc/self/root/usr/bin/npx`, then disabled the sandbox entirely once caught.
- Cline (5M+ VS Code extension users) was compromised via a prompt-injection attack chain that exfiltrated an npm token.
- Claude Code had a SOCKS5 hostname null-byte injection bug that bypassed network allow-lists undetected for 5.5 months.

## 2. Attacker / failure models

Damping must reason about three distinct classes, which are often conflated in casual discussion:

### 2.1 A confused or careless agent (no adversary)
The agent itself, acting in good faith on an ambiguous or overly broad instruction, issues a destructive command. This is the majority of the incidents above. Defense: the core interception + policy + confirm-prompt flow (Phase 1).

### 2.2 A manipulated agent (indirect prompt injection)
Content the agent reads (a file, a web page, an MCP tool's output) contains an instruction that causes the agent to take an unintended destructive action, or to poison its own memory so a *later*, seemingly unrelated action becomes dangerous (see §5, Memory & Context Poisoning). Defense: policy engine doesn't trust "the agent said it's fine" — it evaluates the actual command/tool-call regardless of why the agent decided to issue it.

### 2.3 Damping itself as the target
Once an agent (or an attacker directing one) becomes aware a safety layer exists, the rational move is to disable it, not fight it. This is not hypothetical — see the Ona incident referenced in the original planning docs, where an agent discovered a safety layer and simply turned it off. Damping's self-protection requirements (§4) exist specifically for this class.

## 3. Known bypass techniques Damping must defend against (and test for)

Each of these must have a corresponding **"confirmed still blocked"** test case in `features/`, and any newly discovered bypass gets a new scenario added immediately — permanent regression protection, never a one-off fix.

| Technique | Why naive detection misses it | Damping's defense |
| --- | --- | --- |
| Regex-evadable formatting (`r''m -rf`, extra whitespace, quoting tricks) | Regex matching on raw strings is trivially defeated by shell-legal formatting variance | AST-based parsing via mvdan/sh — structure is normalized regardless of surface formatting |
| Multi-line script wrappers hiding `rm -rf` inside a larger heredoc/function | Naive single-line regex never sees the embedded line | mvdan/sh parses the full AST including heredocs and function bodies; the danger-detection pass walks the whole tree, not just the top-level command |
| Variable expansion / command substitution (`$(echo rm) -rf /`) | String matching doesn't resolve substitution structure | AST distinguishes `CmdSubst` nodes explicitly; policy treats dynamically-constructed command names as at least `ask`-tier by default (can't prove intent statically) |
| Shell aliases resolving to dangerous commands | mvdan/sh's `syntax` package does **not** expand aliases (only the `interp` interpreter does, which means actually executing — not acceptable for a pre-execution check) | Maintained alias-lookup table for common dangerous aliases; documented as a known limitation, not silently assumed solved by "we parse AST" |
| Base64/encoded payloads (`echo <b64> | base64 -d | sh`) | The dangerous content is runtime data, invisible to a static parser | Structural rule: any pipeline containing `base64 -d`/`base64 --decode` (or similar encode/decode primitives) feeding into `sh`/`bash`/`zsh`/`eval`/`source` is flagged as at least `ask`-tier, regardless of decoded content |
| `/proc/self/root/...`, `/proc/self/exe` sandbox-bypass paths | Parser sees an opaque string literal, no special meaning | Maintained string-match list of known bypass paths, checked independently of AST semantics |
| `curl | sh` / `wget | sh` installer pipelines | Legitimate use exists (this is how Damping itself is installed!), so blanket blocking causes unacceptable false positives | Default policy treats `curl|sh` piping to `sh`/`bash` from a **non-allowlisted domain** as `ask`-tier; Damping's own install docs are the canonical example of what an allowlisted, user-initiated install pipeline looks like — this asymmetry must be called out explicitly in the policy comments so contributors don't "fix" it into a hard block |

## 4. Damping cannot be silently disabled (self-protection)

Requirement, not aspiration: an agent operating inside a session must not be able to turn off enforcement without the *human* being made aware. Concretely:

- Policy file and hook registration in `~/.claude/settings.json` / `.cursor/hooks.json` should be checked for tampering by `damping doctor`, which is designed to be run frequently and as part of `damping init`'s final step.
- `damping off` is the only sanctioned way to disable enforcement, and it is a deliberate, explicit CLI invocation by a human at a terminal — not something reachable via a Bash tool call the agent itself can issue, because the CLI binary itself is not typically on the list of commands an agent would be instructed to run for a legitimate reason, and `damping off` prints a loud, hard-to-miss warning plus writes an audit entry with `action_type: self_disable`.
- If Damping detects its own hook entry has been removed from the agent's settings file since the last `damping doctor` run (i.e., something *other* than `damping off` disabled it), it surfaces this loudly on the next `damping doctor` invocation — this is the direct, named mitigation for the Ona-style "agent discovers and removes its own safety layer" failure mode. This stateful before/after comparison is `damping doctor`'s job specifically (it persists `doctorState` between runs — see `cli/cmd/doctor.go`); `damping status` is a quick, stateless, current-instant summary and does not track or flag this on its own — run `damping doctor` for the actual security check.

## 5. Adjacent threat class tracked for later phases: Memory & Context Poisoning (ASI06)

Not in scope for Phase 1-3, but documented here because Tim has flagged it as the most actively interesting extension (see `市場調查與現況總覽.md` §11) and the same `core/policy` + `core/audit` spine is meant to extend into it in Phase 6 without a redesign. Real, verified threat data (not speculative):
- MINJA: memory poisoning via normal conversational interaction, 95-98% success rate.
- AgentPoison: <0.1% poisoning rate achieves >80% attack success, no retraining needed.
- PoisonedRAG: 5 malicious documents against a million-document corpus achieves 91-99% attack success.
- Real financial-sector case (GoPlus Security): an agent was induced to "remember a preference" (e.g. "usually proactively refund"), later triggered into unauthorized fund transfers via a vague "handle it as usual" instruction.

When Phase 6 starts, `ActionEvent.ActionType = memory_write` (already reserved in the schema, see `docs/architecture.md` §3) becomes a first-class interception point, with a provenance/trust score attached rather than the binary allow/deny used for shell/tool actions.

## 6. Fail-open vs. fail-closed — an explicit, non-negotiable design split

Two different questions get conflated if this isn't stated explicitly:

1. **"Is this action dangerous?"** — the actual policy judgment. Default posture: conservative, prefer under-blocking to over-annoying (per the "false positives are the #1 enemy" principle), because a tool that nags constantly gets uninstalled, and an uninstalled tool protects nobody.
2. **"Damping itself just failed internally (parser crash, corrupt policy YAML, hook process timeout) — what happens to the action?"** — This is answered by forces outside Damping's control: both Claude Code and Cursor's hook contracts fail open on anything other than exit code 2 (see `docs/cli-reference.md` §Hook Contract). Damping cannot force a fail-closed outcome here even if it wanted to — the surrounding agent decides. Damping's actual responsibility in this failure mode is to make the degradation **loud and logged**, not to pretend it can silently guarantee fail-closed: every internal failure writes an audit record with `decision.degraded = true`, and `damping doctor` treats "any degraded event since last check" as a hard warning, not a footnote.

## 7. Confused deputy (Phase 3, MCP Gateway)

Documented here for continuity even though it's a Phase 3 concern: the Gateway must never forward a client's MCP token directly to a downstream server. Each downstream MCP server gets its own audience-bound token, re-issued by the Gateway after the client's original token is validated — this prevents a token scoped to Server A from being replayed against Server B. V1's thin MCP adapter (`cli/adapter/mcp`) does not handle tokens at all (see `docs/architecture.md` §7), so this class does not apply until Phase 3.

## 8. Policy tampering

The policy YAML file itself is a target — if an agent (or an attacker-controlled process) can rewrite `~/.damping/policy.yaml` to remove a rule, the rule might as well not exist. V1 mitigation: `damping doctor` computes and displays a hash of the active policy file and flags unexpected changes since the last run (informational in V1 — the user is the root of trust on their own machine, so this is a tamper-evidence measure, not tamper-prevention). Phase 5 (enterprise, centrally-managed policy) upgrades this to signed policy bundles distributed from the team/enterprise control plane, where tamper-evidence becomes tamper-*resistance* because the local user is no longer the sole trust root.

Writes to the policy file itself (`core/policy.AppendAlwaysPattern`, used by the `[A]`/`[D]` prompt responses) go through a temp-file-then-rename, so a crash mid-write can never leave a truncated or corrupt file behind — but this does not serialize two *concurrent* writers (e.g. the CLI hook and `damping mcp wrap` both persisting a pattern at the same instant); the later rename simply wins. Given how rarely two such writes land in the same instant on one developer's machine, this is treated as an acceptable known gap rather than something requiring a cross-process file lock in V1.

## 9. Concurrent TTY prompts within one process

A single long-running `damping mcp wrap` process can have the MCP SDK dispatch multiple simultaneous tool calls, each potentially needing a `Prompt`-tier confirmation. `cli/adapter/mcp`'s `ttyPromptMu` mutex serializes these so two prompts never interleave their text/input on the same terminal within that one process. This does **not** cover a genuinely separate `damping` process (e.g. the CLI hook firing at the same instant as `mcp wrap`) prompting on the same terminal — that cross-process race remains a known, low-priority limitation, consistent with §8's treatment of concurrent policy-file writes.
