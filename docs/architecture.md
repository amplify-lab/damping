# Damping — Architecture Reference

> Source of truth for repo layout, module naming, and the `ActionEvent` schema. Strategic rationale lives in `docs/00-統一開發計畫（定案版）.md` (Chinese); this document is the English, code-facing companion so external contributors don't need to read the Chinese planning docs to build against the core.

## 1. Repository layout

```
/damping (repo root — this directory)
├── go.work
├── core/                    # Go module: transport-agnostic policy engine + event schema
│   ├── event/               # ActionEvent, Channel/ActionType/RiskLevel (action_event.go), New()+NewID() constructors (build.go)
│   ├── decision/            # Verdict, Decision
│   ├── policy/              # Facts + Evaluator interface + Engine.Evaluate (policy.go), Config load/validate (config.go),
│   │                         #   always-allow/deny persistence (persist.go), always-pattern matching (patterns.go),
│   │                         #   rule registry (rules.go) + matchers split by transport (rules_shell.go, rules_mcp.go —
│   │                         #   each transport's rule family grows independently, see §4), OPAEngine + embedded
│   │                         #   Rego module (opa.go, policy.rego) — Phase 3, see §4
│   ├── atomicfile/            # Write() — temp-file+rename crash-safe write, shared by policy's
│   │                         #   AppendAlwaysPattern and cli/adapter/agent's hook installers (both
│   │                         #   overwrite an existing file in place and needed the identical fix)
│   └── audit/                # Append-only JSONL sink + reader/filter; Writer.Append also rotates
│                             #   via Rotate() once the file crosses a size threshold
├── cli/                     # Go module: `damping` binary (product line A)
│   ├── cmd/                 # Cobra command tree — one file per command (init.go, doctor.go, log.go, ...)
│   ├── shell/                # AST traversal (parser.go), Facts extraction (facts.go), static-value
│   │                         #   resolution (literal.go) — see §5
│   ├── adapter/hook/         # shared evaluate/build-event logic used by `policy test` and the real CLI hook
│   ├── adapter/mcp/          # V1 thin MCP adapter — protocol wiring (wrap.go), Facts extraction (facts.go) — see §7
│   ├── adapter/agent/        # Claude Code / Cursor hook-file install & detection; shared JSON-file
│   │                         #   read/write (jsonfile.go) so it isn't mistaken for Claude-Code-specific
│   ├── paths/                 # ~/.damping/* path resolution ($DAMPING_HOME override for tests), plus
│   │                         #   ClaudeSettings()/CursorHooks() (agent hook config paths, same override pattern)
│   ├── enforcement/           # IsDisabled() — whether `damping off` is currently in effect. Split out of
│   │                         #   cmd/onoff.go specifically so cli/dashboard can ask the same question
│   │                         #   without importing cli/cmd (which imports cli/dashboard to wire the command)
│   ├── dashboard/             # `damping dashboard` — a LOCAL, single-user audit-log viewer (Go html + a
│   │                         #   Tailwind-compiled static/dashboard.css, go:embed'd, no Node at build/run
│   │                         #   time). NOT the same thing as the root-level dashboard/ below — this one
│   │                         #   is fully unauthenticated, localhost-only, zero-infrastructure, and exists
│   │                         #   today; see its own package doc comment (server.go) for how it relates to
│   │                         #   Phase 4's team dashboard
│   ├── policies/              # canonical default.yaml + go:embed wrapper (see note below)
│   └── ui/                   # Prompter interface + TTYPrompter (prompt.go), /dev/tty opening split by
│                             #   build tag (tty_unix.go, tty_windows.go) — shared by cmd/hook.go and adapter/mcp
├── gateway/                 # NOT YET SCAFFOLDED — Phase 3 Go module: MCPWarden Gateway (Track B)
├── cf/                      # NOT YET SCAFFOLDED — Phase 4 TypeScript: Cloudflare Workers (Track A)
├── dashboard/               # NOT YET SCAFFOLDED — Phase 4 React+TS team dashboard (Cloudflare-backed,
│                            #   SSO auth, team sync — see docs/ux-dashboard-spec.md). Not to be confused
│                            #   with cli/dashboard/ above, which is a local single-user viewer that
│                            #   already exists and needs none of Phase 4's infrastructure
├── features/                # Gherkin .feature files (godog), shared across the whole project
├── docs/                    # Planning + reference docs (this file, threat model, CLI reference, UX spec)
└── .github/workflows/       # CI: lint, unit test, BDD, gosec, SBOM
```

**Note on `policies/`**: the canonical `default.yaml` lives at `cli/policies/default.yaml`, not a repo-root `policies/` directory as earlier planning drafts assumed. `go:embed` requires an embedded file to live inside the embedding package's own module tree (no `..` in embed patterns), and the shipped binary must embed its default policy rather than read a repo-relative path that won't exist after `go install`/`brew install`. `core/policy`'s own tests load this exact same file by relative path, so the shipped default and the tested default can never drift apart. Phase 3's Rego module (`core/policy/policy.rego`) follows the identical constraint and lives inside `core/policy/` itself, embedded via its own `//go:embed policy.rego` directive (see §4) — not loaded at runtime from a separate directory as an earlier draft of this note assumed.

`gateway/`, `cf/`, and `dashboard/` are intentionally **not scaffolded yet** — they belong to Phase 3+ per `docs/00-統一開發計畫（定案版）.md` §5. Creating empty module skeletons for phases that are months away would be premature structure with no code to anchor it; scaffold them when their phase starts, following the same module-naming convention below.

## 2. Module naming (placeholder, pending Tim's GitHub org confirmation)

Research turned up a live but dormant `github.com/damping` account (see the master plan §二) — GitHub org/user names share one namespace, so that handle likely cannot be claimed outright. **Recommendation: org = `amplify-lab`, repo = `damping`.**

```
module github.com/amplify-lab/damping/core
module github.com/amplify-lab/damping/cli
```

If Tim confirms a different org, this is a single `find . -name go.mod -o -name '*.go' | xargs sed -i 's#github.com/amplify-lab/damping#github.com/<final-org>/damping#g'` away from being renamed — nothing else in the architecture depends on the exact string.

## 3. `core/event` — the ActionEvent schema (one-time design, load-bearing)

This is the single normalized shape every adapter (CLI hook, MCP wrapper, future HTTP proxy) converts its intercepted action into before it ever touches `core/policy` or `core/audit`. **No adapter writes audit records directly — `core/audit` is the only writer.** Getting this schema right now avoids a rewrite when enterprise compliance reports (Phase 5) need fields that were never captured.

```go
// core/event/action_event.go
package event

import "time"

type Channel string

const (
	ChannelCLI  Channel = "cli"
	ChannelMCP  Channel = "mcp"
	ChannelHTTP Channel = "http" // reserved, Phase 3+
)

type ActionType string

const (
	ActionShellExec   ActionType = "shell_exec"
	ActionToolCall    ActionType = "tool_call"
	ActionHTTPRequest ActionType = "http_request" // reserved, Phase 3+
	ActionMemoryWrite ActionType = "memory_write" // reserved, Phase 6 (Memory Guard)
	ActionSelfDisable ActionType = "self_disable" // a `damping off` invocation — the audit trail's own most security-sensitive entry
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// ActionEvent is the transport-agnostic record every adapter normalizes into.
// Field set is sized for Phase 5 compliance reports from day one — do not add
// fields later without a migration plan for existing ~/.damping/audit.jsonl files.
type ActionEvent struct {
	EventID    string            `json:"event_id"`
	Timestamp  time.Time         `json:"timestamp"`
	SessionID  string            `json:"session_id"`
	Actor      string            `json:"actor"`              // which agent/process (e.g. "claude-code", "cursor")
	Identity   string            `json:"identity,omitempty"` // empty in individual tier; populated once AD/LDAP is wired in Phase 5
	Channel    Channel           `json:"channel"`
	ActionType ActionType        `json:"action_type"`
	Target     string            `json:"target"` // path / tool name / URL
	Raw        string            `json:"raw"`    // original command / call payload, for forensics
	ParsedArgs map[string]any    `json:"parsed_args,omitempty"`
	RiskLevel  RiskLevel         `json:"risk_level"`
	Decision   decision.Decision `json:"decision"` // embeds Verdict + PolicyID + Reason + Degraded — see below
}
```

```go
// core/decision/decision.go
package decision

type Verdict string

const (
	Allow  Verdict = "allow"
	Deny   Verdict = "deny"
	Prompt Verdict = "prompt"
)

// Decision is what core/policy.Evaluate returns. A Prompt verdict is later
// resolved to Allow/Deny by a human at the TTY (cli/ui) — ResolvedVerdict
// captures that outcome so the audit trail ends up with ONE coherent record
// instead of two disjoint ones (Outcome() returns ResolvedVerdict if set,
// else Verdict).
type Decision struct {
	Verdict         Verdict `json:"verdict"`
	ResolvedVerdict Verdict `json:"resolved_verdict,omitempty"`
	PolicyID        string  `json:"policy_id,omitempty"`
	Reason          string  `json:"reason,omitempty"`
	// Degraded marks a decision made under an internal Damping failure (parser
	// crash, corrupt policy file, hook timeout) rather than a real policy match.
	// See docs/00-統一開發計畫（定案版）.md §六 on fail-open vs fail-closed —
	// external hook contracts (Claude Code, Cursor) fail open on non-2 exit
	// codes, so Damping's own responsibility is to make degraded mode loud,
	// not to pretend it can force a fail-closed outcome it doesn't control.
	Degraded bool `json:"degraded,omitempty"`
}
```

`core/event` imports `core/decision` rather than redefining its own copy — `ActionEvent.Decision` is a `decision.Decision` value, so the policy engine's output and the persisted audit record are the exact same type, with no separate `DecisionRecord`/conversion step to keep in sync. `core/policy`'s `Evaluate()` returns a `decision.Decision`; `cli/adapter/hook.BuildActionEvent` embeds it into an `ActionEvent` only once — after any TTY resolution of a `Prompt` verdict has already happened — which is what makes "one coherent record per action" true in the actual audit log, not just an aspiration (see `core/audit`'s tests and `features/audit_log.feature`).

## 4. `core/policy` — Evaluator interface: Go-native rules + OPA/Rego (Phase 3, **implemented**)

`policy.Evaluator` (`Evaluate(f Facts) decision.Decision`) is the one interface every adapter (`cli/adapter/hook`, `cli/adapter/mcp`) depends on — never a concrete engine type. Two implementations satisfy it:

- **`Engine`** (V1, default): hardcoded Go matchers in `rules_shell.go`/`rules_mcp.go`/`rules_selfprotection.go`, registered by rule id in `rules.go`. Zero extra dependencies, sub-100ns per `Evaluate` call — the right choice for the individual-tier CLI's one-shot hook subprocess.
- **`OPAEngine`** (Phase 3): the same 12 rules translated into Rego (`policy.rego`, embedded via `go:embed`), evaluated through `open-policy-agent/opa/rego` in-process (no network hop, no server). Real policy-as-code for Gateway/enterprise deployments that need to audit or extend rules without a Go recompile.

`Config.Engine` (`native` | `opa`, default `native`) selects which one `policy.NewEvaluator(ctx, cfg)` constructs — every call site goes through that one function, so switching backends is a `policy.yaml` edit, never a rewrite of call sites. `OPAEngine.Evaluate` compiles down to: reuse the exact same Go `matchesAnyPattern` (from `patterns.go`) for the `always_allow`/`always_deny` override tier — that's simple user-authored glob matching, not policy-as-code logic, so duplicating it in Rego would just be a second implementation to keep in sync — then ask Rego's `data.damping.policy.matches` for the *set* of every rule id that matches, then walk `cfg.Rules` in order to pick the first match, mirroring `Engine.Evaluate`'s sequential first-match semantics exactly (Rego's set-based rules are naturally unordered, so "which one wins when several match" stays a thin, order-dependent Go post-processing step rather than something forced into Rego).

`core/policy/opa_equivalence_test.go` is the "keep Phase 1's tests green when swapping to OPA" contract: every `Facts`/`Config` case the Go-native `Engine` is tested against also runs through `OPAEngine`, asserting byte-identical `Decision` output. `core/policy/opa_bench_test.go` gates eval latency at sub-millisecond per call (`OPAEngine.Evaluate` benchmarks in the tens of microseconds — comfortably inside budget; `Engine.Evaluate` stays in the tens of nanoseconds, since native has no interpreter overhead at all).

## 5. `cli/shell` — AST parsing + semantic bypass detection

Built on `mvdan.cc/sh/v3/syntax`. Two layers, not one:

1. **Syntax layer (mvdan/sh AST)**: reliably defeats naive regex-bypass tricks — extra whitespace, quoting variations, variable expansion structure, multi-line wrapping. `parser.go`'s walk also recurses into every command/process substitution wherever a word can carry one (argument, assignment value, redirect target, here-string — not just the command-name position) and re-parses a heredoc body as its own script whenever it's addressed to a real shell interpreter (`sh`/`bash`/`zsh`/`dash`/`ksh` — a heredoc fed to a non-shell command like `cat` is left as inert data). This is what "parse, don't regex" actually buys you.
2. **Semantic layer (hand-written, on top of the AST)**: mvdan/sh's `syntax` package does **not** resolve shell aliases (only the opt-in `interp` interpreter does, which means actually executing), does **not** decode runtime data like base64 payloads, and treats `/proc/self/...` paths as opaque string literals. These are real, documented gaps (see `docs/threat-model.md`), covered instead by:
   - a small, deliberately extensible alias-lookup table demonstrating the resolution mechanism (`facts.go`'s `knownAliases`, resolved consistently for both a lone command and a pipeline stage) — not a claim of comprehensive dotfile-framework coverage,
   - a structural rule flagging a `base64`/`base32`/`uudecode` (unambiguous bare command names) or `xxd -r`/`openssl enc -d`/`openssl base64 -d` (ambiguous tools, matched by a targeted flag pattern instead) pipeline feeding into `sh`/`bash`/`zsh`/`eval`/`source`, regardless of the payload content,
   - a maintained string-match list of known sandbox-bypass paths (`/proc/self/root/...`, `/proc/self/exe`, etc).

`rm -rf`'s target check (`rules_shell.go`'s `matchRmRfProtected`) inspects every non-flag path operand independently, not just the last word — `rm` accepts multiple path operands in one invocation, and checking only the last word both false-positived on a trailing flag (`rm -rf node_modules -v`) and silently missed a dangerous earlier operand (`rm -rf /etc build`), a real bug found via review and fixed.

`Analyze` — not each rule individually, which would just fragment the same coverage — has real Go native fuzz coverage (`cli/shell/fuzz_test.go`'s `FuzzAnalyze`), seeded from every real bypass this package's tests assert on and run through the full `Analyze` → `Engine.Evaluate` pipeline every seed and mutation, on every rule at once; CI runs it for 30s per PR, longer locally. "Must never trigger" regressions live as ordinary Go tests (e.g. `TestAnalyze_AllowsSafeEverydayCommands`) — see `docs/00-統一開發計畫（定案版）.md` §六 and the test strategy in the original `開發計畫.md`.

## 6. `cli/cmd` hook entrypoint — Claude Code / Cursor integration contract

See `docs/cli-reference.md` §11 for the exact wire format. Summary: both agents only treat **exit code 2** as blocking; any other non-zero code fails open (action proceeds).

**Important correction from an earlier draft of this doc**: the hook's stdin/stdout are already reserved for the JSON protocol with Claude Code itself, so a `Prompt`-tier decision cannot be resolved by returning `permissionDecision: "ask"` and asking Claude Code to show its own generic prompt — that would silently replace Damping's own branded confirmation UI (§12 of the CLI reference) with a different one Damping doesn't control. Instead, Damping opens the controlling terminal directly (`/dev/tty` on Unix, via `cli/ui.OpenTTYPrompter` — the per-OS split lives in `cli/ui/tty_unix.go`/`tty_windows.go`, not in `cli/cmd`, specifically so `cli/adapter/mcp` can reuse the exact same prompter instead of duplicating it) for the interactive prompt, resolves the decision fully, and only then responds to Claude Code with a plain exit code — the hook never actually returns `"ask"` to the agent in V1. If no controlling terminal is available (e.g. a headless/CI execution context), a `Prompt`-tier decision defaults to `Deny` rather than either hanging or silently allowing. In every case:
- exit `2` with a human-readable reason on stderr for a hard deny (including a resolved-to-deny prompt, or the no-TTY fallback),
- exit `0` for allow (directly, or resolved from a prompt) — no JSON needed on this path in V1,
- never let an internal crash silently look like a normal allow — write a `degraded` audit record even when the external agent will fail open regardless.

## 7. `cli/adapter/mcp` — V1 thin adapter (not a gateway) — **implemented**

The official `github.com/modelcontextprotocol/go-sdk` has no built-in interceptor/middleware hook point — it's a "register tools" SDK, not a "wrap existing calls" SDK. So `damping mcp wrap -- <server-command>` is a real client+server pair (`wrap.go`'s `wrapTransport`): it connects to the real server as an `mcp.Client` (over a `CommandTransport` subprocess), discovers its tools via `ClientSession.Tools` (auto-paginating), and re-exposes each one, unmodified, on an `mcp.Server` running over this process's own stdin/stdout (`StdioTransport`). Every forwarded tool's handler (`registerForwardingTool`) normalizes the call into `policy.Facts` (`facts.go`), runs it through the exact same `core/policy` engine and `core/audit` sink the CLI hook uses, and — only on `allow` (directly or resolved from a `Prompt` via the same `/dev/tty` mechanism as §6) — forwards the call to the real server via `ClientSession.CallTool`, returning its result unmodified. A `deny` never reaches the real server at all; it comes back as a normal `CallToolResult{IsError:true}` so the calling LLM sees a legible refusal rather than a protocol-level error.

An `[A]`/`[D]` "always" choice at the prompt persists exactly like the CLI hook's (`policy.AppendAlwaysPattern` writes it into the same policy file), but `damping mcp wrap` is one long-lived process for an entire MCP session rather than a fresh subprocess per action — so writing to disk alone wouldn't make "always" true for the *rest of this session*, only for a hypothetical future run that reloads the file. `always_overlay.go`'s `alwaysOverlay` closes that gap: a small in-memory, mutex-guarded mirror of what was just persisted, checked before `engine.Evaluate` on every subsequent call in the same session, one instance shared across every tool `wrapTransport` registers.

No OAuth, no token inspection or re-issuance, no confused-deputy defense — that's Phase 3's `gateway/`, an actual standalone reverse-proxy MCP server, not this in-process pair.

`registerForwardingTool`'s handler checks `enforcement.IsDisabled()` fresh on *every* call, not just once when `wrapTransport` starts — a real bug found via review: unlike the CLI hook (a fresh subprocess per command, so a startup-only check there already amounts to "check every call"), `mcp wrap` is one long-lived process, and `damping off` mid-session must take effect immediately, the same way it does for the CLI. When disabled, the call is forwarded straight through with no evaluation and no audit record — matching `docs/cli-reference.md` §6's claim that agent commands "will NOT be checked."

**The one default-active MCP rule (`mcp.destructive_tool_call`) deliberately does not need identity.** It fires only when the wrapped server itself sets `ToolAnnotations.DestructiveHint: true` — a signal that requires no AD/LDAP binding to be meaningful. The identity-gated rule (`mcp.write_tool_unscoped_identity`) is fully implemented in `core/policy/rules_mcp.go` but is **not** in `cli/policies/default.yaml`'s active rule list: with no identity system at the individual tier (`ActionEvent.Identity` is always empty pre-Phase 5), it would flag nearly every non-explicitly-read-only tool call — the exact nagging failure mode this project treats as its top product risk. Phase 5's enterprise policy config re-enables it once identity binding makes "unscoped" a real signal.

Testing this without real subprocesses uses the SDK's `mcp.NewInMemoryTransports()` — two paired transports connecting a fake "real" MCP server directly to `wrapTransport`, and a second pair connecting `wrapTransport` to a test client — see `wrap_test.go`. This proves the actual product claim end-to-end (not just unit-tested in isolation): a destructive tool call is denied before ever reaching the fake server, and a CLI-channel event plus an MCP-channel event both land in one audit file, distinguishable only by `Channel`.

## 8. CI pipeline (`.github/workflows/ci.yml`, `release.yml`)

Per PR (`ci.yml`): `golangci-lint` (incl. `gosec`) → `go test ./...` → SBOM generation (`cyclonedx-gomod`). The `godog` BDD run against every V1-scope `features/*.feature` file (§7's `cli/bdd` package) isn't a separate pipeline step — it's a normal Go test package, so `go test ./...` already runs it, with the same pass/fail semantics as everything else in that step. Any failure blocks merge. Dependabot on; npm publishing (once `cf/`/`dashboard/` exist) goes through OIDC provenance, not long-lived tokens — a direct lesson from the 2026 Cline token-theft incident referenced in the original planning docs.

Release engineering (`release.yml`, `.goreleaser.yaml`, `install.sh`) is a separate workflow, triggered on `v*` tags rather than every PR: cross-platform builds (linux/darwin, amd64/arm64), a Homebrew cask, and the one-line install script README.md's Quick Start assumes, with real sha256 checksum verification (see README.md's "What's real right now" section for what's been verified end-to-end vs. still pending Tim's GitHub org/domain confirmation). A `release-check` job in `ci.yml` snapshot-builds on every PR so a broken release config fails fast, without actually publishing anything.
