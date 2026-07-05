# Damping Infrastructure & Architecture Research Synthesis

*Consolidating four independent research passes: Phase 3 (OAuth/Gateway), Phase 4 (Cloudflare + SSO), Phase 5 (enterprise control plane), Phase 6 (memory-poisoning defense spec). Compiled July 2026, at Tim's request, specifically asking for a neutral, evidence-based assessment rather than confirmation of his own self-hosting-leaning instinct. Not yet a final decision — a research input for Tim to decide from.*

---

## 1. Executive Summary

- **Phase 3 (OAuth/IdP):** Build the Gateway's token-issuance core on **Ory Hydra (+ Fosite), self-hosted** — it's Go-native (the team can read and patch it), cheap to operate relative to Keycloak, and keeps the security-critical audience-binding logic in-house. Evaluate **Zitadel** in the same spike as a fallback if Hydra's resource-indicator gap is costly to close. Explicitly reject Keycloak (JVM ops burden) as the default and don't lead with a pure vendor for this specific piece.
- **Phase 3 (SSO front-door):** Separately, plan to offer **WorkOS AuthKit** later as an optional enterprise SSO/federation layer for customers plugging in their own Okta/Entra/Google Workspace — commodity plumbing, good to buy.
- **Phase 4 (hosting):** **Stay on Cloudflare** (Workers + Pages + D1 + KV + R2) for the team dashboard, but explicitly architect the audit-event store as a bounded per-tenant D1 "hot window" + R2 archival tier from day one, and keep the dashboard's availability fully decoupled from the CLI's live policy-decision path.
- **Phase 4 (enterprise SSO):** Do **not** build a custom SAML/OIDC broker and do **not** self-host Keycloak/Ory for this. Use **WorkOS AuthKit** as the enterprise-IdP integration layer (Clerk as a cheaper fallback if its self-serve admin depth suffices). This is the clearest exception to Tim's self-hosting default, and it's deliberate, not an oversight.
- **Phase 5 (control plane):** Adopt a **hybrid/open-core architecture** — core/cli (interception + policy evaluation) stays permissively licensed and open forever; the new Phase 5 control-plane module (policy authoring, fleet management, SSO, signed-bundle distribution, audit rollup) ships as **one codebase, two deployment modes**: self-hosted (license-gated, for regulated/air-gapped buyers) and Damping-hosted (subscription SaaS, for everyone else) — mirroring Teleport/GitLab/Vault's converged pattern, not GitLab's full monolith or HashiCorp's fully-closed model.
- **Phase 5 (bundles):** Reuse OPA's existing signed-bundle wire protocol (already embedded in Damping) rather than inventing a new one; fix its two known weak points (single static signing key, no rollback) by adding rotatable multi-key verification, Ed25519 by default, and Styra-DAS-style versioned rollback.
- **Phase 6 (memory poisoning):** The real blocker isn't the scoring model, it's visibility — `cli/cmd/hook.go` currently only observes `Bash` calls, so it never sees the `Edit`/`Write`/`MultiEdit` calls that actually write to CLAUDE.md/`.cursor/rules`. Widen that filter first. Layer in deterministic, dependency-free provenance tagging + trust scoring + structural (GoPlus-style) pattern detection, additive to the existing `Facts`/`Decision` schema, with a new non-blocking `ReviewRequired` flag rather than a new blocking verdict. The temporal retrieval-time attack (poison now, trigger weeks later) is **not solvable** by any write-time control Damping can build unilaterally.
- **Cross-cutting theme:** Tim's self-hosting instinct is well-founded exactly where the software *is* Damping's core security claim (the OAuth token-issuance/audience-binding engine, the policy engine, the enforcement path) — and weaker where the problem is a long-tail, ever-growing *integration/support* burden with third-party systems Damping doesn't control (enterprise SAML/SSO quirks per IdP). See Section 6.

---

## 2. Phase 3 — OAuth Provider

**Scope:** Choosing the OAuth 2.1 / identity-provider foundation for the Phase 3 Gateway, whose core security mechanism is confused-deputy defense via RFC 8707 (resource indicators) + RFC 8693 (token exchange) — i.e., minting a downstream-server-audience-bound token from a client's Gateway-audience token, for a multi-tenant enterprise product with a Go backend.

### Comparison

| Option | Type | Language fit | RFC 8693 (token exchange) | RFC 8707 (resource indicators) | Multi-tenancy | Notable risk |
|---|---|---|---|---|---|---|
| **Ory Hydra + Fosite** | self-hosted | Go — native, embeddable as a library | Documented, supported | Unclear/needs spike | BYO (headless) | No admin UI; needs building |
| **Zitadel** | self-hosted | Go, official SDK | Documented, supported | **Hard blocker** — `resource` param returns `invalid_target` today | Best-in-class (Organizations/Projects) | Resource-indicator gap is explicit, not just undocumented |
| **Keycloak** | self-hosted | Java — mismatch | GA since 26.2 (May 2025) | Not implemented; workaround via Audience mapper | Realms (coarse) | Real CVEs requiring same-week patching (CVE-2025-3501, CVE-2025-11419); 3-yr TCO ~$142k–$211k incl. labor |
| **authentik** | self-hosted | Python — mismatch | No evidence found | No evidence found | Schema-per-tenant since 2024.2 | Design center is internal SSO, not B2B AS; documented multi-tenant issuer bug |
| **FusionAuth** | hybrid | Java (lighter) | Previously advertised, needs confirming | Not strongly documented | OK | Smaller ecosystem; less battle-tested for this exact use case |
| **Ory Network (managed)** | managed-SaaS | Same codebase as Hydra | Same as Hydra | Same gap as Hydra | — | Lowest lock-in of any managed option (identical code, reversible) |
| **WorkOS AuthKit** | managed-SaaS | REST/JWT, Go-agnostic | **Not confirmed** — the harder half of the requirement | **Supported** — audience binding via `resource`→`aud` | N/A (per-connection SSO) | Explicitly built for MCP auth scenarios; free to 1M MAU |
| **Auth0 (Okta)** | managed-SaaS | REST | Custom via Actions only | Custom only | Enterprise-grade | Documented "growth penalty" pricing; $5k–$34k/yr per extra SSO bundle |
| **Clerk** | managed-SaaS | REST | No evidence found | No evidence found | Per-org billing >100 orgs | Center of gravity is web-app auth, not M2M/MCP token issuance |

### Recommendation

Build the Gateway's core token-issuance/audience-binding engine on **Ory Hydra (Fosite embeddable for tighter control), self-hosted, as the default**. In the same short spike, evaluate **Zitadel** for its stronger native multi-tenancy if Hydra's resource-indicator behavior proves costly to close. **Do not adopt Keycloak** (Java/ops-burden mismatch for a small Go team) and **do not lead with a pure vendor** (Auth0/Clerk/WorkOS) as the sole identity layer for the security-critical token-exchange core. Separately, plan to offer **WorkOS AuthKit** later as an optional SSO/federation front-door for enterprise customers who want to plug in their own Okta/Entra/Google Workspace — that commodity federation layer is a good vendor candidate even though the core AS stays self-owned.

### Why

1. **No option has clean, joint, out-of-the-box support for RFC 8707 + RFC 8693 together.** Every candidate needs a spike and likely custom code, self-hosted or not — this flattens the usual "vendor gives you turnkey compliance" argument for buying.
2. **Because custom work is unavoidable, language fit becomes the deciding practical factor.** Hydra/Fosite and Zitadel let Damping's own engineers read, extend, and even embed the audience-binding logic — arguably the single most security-critical piece of code in the whole Gateway. Keycloak (Java), authentik (Python), and vendor internals put that logic behind a language or a black box the team can't directly own.
3. **Cost data disqualifies the "obvious" self-hosted default (Keycloak).** Independent 3-year TCO estimates (~$142k–$211k, mostly labor) show that "free" software isn't free when a small team without dedicated IAM/DevOps staff has to operate a JVM cluster and respond same-week to CVEs. Hydra and Zitadel are dramatically lighter Go binaries.
4. **Multi-tenancy favors Zitadel as fallback** if the resource-indicator gap turns out to be the harder blocker in Hydra — its Organizations/Projects model is purpose-built for B2B products serving many enterprise tenants.
5. **On buyer perception:** Damping is a security/guardrail product sold to security teams, and the audience-bound-token engine is the literal mechanism the confused-deputy defense claim rests on — the most security-paranoid or regulated/air-gapped accounts are disproportionately likely to want this self-hostable/auditable rather than trusting an opaque vendor's token-issuance logic. Conversely, the enterprise SSO/SCIM federation layer (connecting into each customer's own IdP) is commodity plumbing where most buyers are equally satisfied whether it's brokered by WorkOS or built in-house — a legitimate place to buy.

### Caveats to re-verify before committing (short hands-on spike, days not weeks)

- Ory Hydra's exact current `resource`-parameter/RFC 8707 conformance (community threads flag edge cases even where token exchange is "fully supported").
- Whether WorkOS AuthKit has (or has roadmapped) a documented RFC 8693 token-exchange endpoint.
- FusionAuth's *current* (not historical) token-exchange conformance.
- Zitadel's roadmap/ETA for resource-indicator support (currently a hard rejection, not a workaround gap).
- Pricing figures across vendors change frequently — re-check before any contract.
- The MCP authorization spec itself is moving (reinforced the resource-indicator mandate again in its 2026-03-15 revision) — re-evaluate the chosen stack in 6–12 months.

---

## 3. Phase 4 — Cloudflare Hosting + SSO

**Scope:** Hosting platform for the Phase 4 multi-tenant team dashboard, and the SSO/enterprise-IdP integration approach.

### 3a. Hosting

| Option | Type | Fit | Key risk |
|---|---|---|---|
| **Cloudflare Workers+Pages+D1+KV+R2** | hybrid | Purpose-fit for lightweight multi-tenant dashboard; ~$4–5/mo at Phase 4 scale; consolidates hosting/frontend/cache/object-storage under one bill | D1's hard 10GB/database cap with no native resharding (SushiData hit this and migrated off); mixed 2025–2026 reliability record with repeated cross-product cascading outages (Jun 12 2025, Nov 18 2025, Dec 5 2025, D1 control-plane errors Aug 2025, Durable Objects incident Jul 3 2026) |
| **Fly.io** | hybrid | Full VM/container control, real Postgres/WebSockets | Dropped free tier; steeper ops; second infra platform to run alongside whatever hosts the CLI |
| **Vercel + Neon/Supabase** | hybrid | Good frontend DX, avoids D1 limits | More vendors stitched together; no compelling fit advantage found for this workload |

**Recommendation:** Stay on Cloudflare. **Design the audit-event store as a bounded per-tenant D1 "hot window" + R2 archival tier from day one** (retrofitting later is the expensive path, doing it now is cheap), and **keep the CLI/gateway's live policy-decision path fully decoupled from dashboard availability** — a Cloudflare incident should degrade reporting, never block agent interception.

### 3b. SSO / Enterprise IdP Integration

| Option | Type | Verdict |
|---|---|---|
| **Custom SAML/OIDC broker (in-house)** | self-hosted | Rejected — SAML is a long-tail per-IdP quirk problem (Okta/Entra/ADFS/Google Workspace/PingFederate/OneLogin all differ despite claiming "SAML 2.0"), cert rotation is a recurring maintenance cost and the most common way enterprise SSO breaks in production; directly trades engineering time away from Damping's actual differentiator |
| **Self-hosted Keycloak** | self-hosted | Full SAML/OIDC/LDAP out of the box, but heavy (2–8GB RAM, 30–60s JVM cold starts), doesn't fit an edge-shaped stack, adds a maintained Java attack surface — ironic for a security product |
| **Self-hosted Ory (Kratos+Hydra+Polis)** | self-hosted | Lightweight Go, philosophically fits — but **core OSS does not support SAML at all**; real SAML coverage means either running the less-vetted Polis component yourself or paying Ory's enterprise tier (~$3k+/mo anyway), which quietly concedes the self-host argument |
| **WorkOS AuthKit — recommended** | managed-SaaS | Purpose-built for exactly this problem (many enterprise IdPs behind one integration); AuthKit free to 1M MAU; SSO/SCIM billed per-connection ($125→$50/mo at volume) scaling with paying enterprise revenue, not baseline usage; **self-serve Admin Portal lets the customer's own IT admin configure the connection** — keeps Damping engineers out of onboarding calls entirely |
| **Clerk** | managed-SaaS | Cheaper on paper at scale (~$1,375/mo vs WorkOS's ~$4,750/mo at one illustrative scale), but less mature self-serve admin portal, and a notable Feb 2026 outage (DNS failover work not yet shipped) |
| **Cloudflare Access for SaaS** | hybrid | Bundled/cheap if already on Cloudflare, but designed for internal org SSO, not external B2B self-serve onboarding; also went down in the same incidents as hosting, so doesn't diversify vendor risk |

**Recommendation:** Do **not** build a custom broker and do **not** self-host Keycloak or Ory for enterprise SSO. Use **WorkOS AuthKit**, with Clerk as a credible cheaper fallback if its self-serve admin depth proves sufficient. **This is the one place in the Phase 4 architecture where the evidence points away from Tim's default self-hosting lean — treat it as a deliberate, reasoned exception, not an oversight.**

### Why

Supporting many enterprise IdPs is a long-tail integration-and-support problem that *grows* with every new enterprise customer — categorically different from self-hosting compute, where the team fully controls the software and failure modes are well understood. Self-hosted alternatives underscore this from both directions: Keycloak solves SAML but at a heavy, mismatched operational cost; Ory is lightweight and Go-native but doesn't solve SAML at all without paying a vendor anyway. WorkOS is free until an actual enterprise deal requires SSO, scales cost with the revenue that triggered the need, and removes Damping engineers from the onboarding path — the single biggest practical difference from every self-hosted option. Buying this one component while continuing to self-host the policy engine, audit data, and core infrastructure is a coherent, defensible split, not an abandonment of the self-hosting philosophy — "run your own servers" and "be SAML-compatible with every enterprise IdP in the wild" are different skills with different risk profiles.

### Caveats

All vendor pricing (WorkOS, Clerk, Ory, Cloudflare) changes frequently — re-verify at decision time. Cloudflare vs. Clerk/WorkOS cost comparisons come from third-party blogs, not vendor head-to-head numbers — directional, not precise. Cloudflare's "Code Orange: Fail Small" resilience initiative was only announced in response to the late-2025 outages and its effectiveness is unproven. Confirm WorkOS covers the actual IdPs of Damping's first few enterprise prospects before committing.

---

## 4. Phase 5 — Enterprise Control-Plane Architecture

**Scope:** Architecture for centrally-managed policy and signed policy bundles, benchmarked against Sentry, GitLab, HashiCorp Vault/Sentinel, Teleport, Infisical, and OPA/Styra DAS.

### Comparison

| Option | Type | Who it satisfies | Cost to Damping | Key drawback |
|---|---|---|---|---|
| **Fully self-hosted (customer runs everything, incl. air-gapped)** | self-hosted | The only model that satisfies the hardest regulated buyers (defense, banks, gov't) for whom multi-tenant SaaS is categorically disqualified | Lowest infra cost, highest per-customer support-engineering cost forever | No natural recurring-subscription motion; shuts out the low-friction "point the CLI at a URL in 10 min" experience most non-regulated customers prefer |
| **Fully managed SaaS only** | managed-SaaS | Individual/SMB segment, fastest to build/monetize | Standard multi-tenant SaaS COGS | Explicitly rejected by the regulated segment Damping is targeting — and Damping's payload (raw shell commands/MCP tool calls, often containing secrets) is arguably *more* sensitive per-byte than typical SaaS telemetry, sharpening this objection, not softening it. Hard product ceiling: no path into air-gapped/classified accounts |
| **Hybrid/open-core — recommended** | hybrid | Both segments, from one codebase | Moderate; hosted option has multi-tenant COGS, self-hosted customers absorb their own infra | Requires real upfront design discipline (stable bundle wire-protocol, licensing-boundary decisions) — done poorly it degenerates into maintaining two divergent products |

Every mature comparable surveyed converges on the hybrid pattern once it serves enterprise: GitLab (one codebase, license-gated tiers, Self-Managed + SaaS + Dedicated), Teleport (same Auth/Proxy binary, Cloud-managed *or* self-hosted, plus "External Audit Storage" letting even Cloud customers keep audit data in their own AWS account), HashiCorp (same Vault Enterprise binary, self-hosted or HCP Vault Dedicated), Styra (open OPA bundle protocol underneath a proprietary DAS governance layer, now also self-hostable as "OPA Control Plane"). Sentry/Infisical prove the rule from the other side — full self-host/cloud feature parity specifically because their buyers include individual/OSS users who must trust the software.

### Recommendation — and its connection to the open-core monetization model already agreed

This maps directly onto Damping's already-agreed open-core split (**public CLI/core, private billing/control-plane**):

1. **`core/` and `cli/`** — the actual command/MCP interception and policy evaluation (both the Go-native and embedded-OPA/Rego engines) — **stay permissively licensed and open, forever.** This is the piece individual developers *and* security-conscious enterprises must be able to inspect to trust a tool that intercepts every shell command before execution. Gating it would undermine adoption in exactly the buyer segment Damping is courting, and it's the part that already cleanly sits on the "public" side of the agreed model.
2. **The Phase 5 control plane** (policy authoring/UI, fleet management, SSO/OAuth 2.1 with audience-bound tokens, signed-bundle build/distribution, multi-tenant audit rollup) is **one new module, deployable two ways from the same codebase**: self-hosted (license-key gated, for regulated/air-gapped buyers — marketed like Vault Enterprise self-managed) and Damping-hosted (subscription SaaS, for everyone else — marketed like Teleport Cloud). This *is* the "private billing/control-plane" side of the already-agreed model — Phase 5 gives it concrete shape: source-available licensing (Sentry-FSL/HashiCorp-BSL style — self-hostable by anyone, but a competitor can't resell it as a hosted offering).
3. **The enforcement point must always be able to run fully offline** against a locally cached, signature-verified policy bundle, independent of where the control plane lives — mirroring Teleport's "managed control plane, customer-owned audit storage" split. This is what actually satisfies air-gap requirements (the command data plane never leaves the customer's premises) without Damping having to fully productize an on-prem control plane for every enterprise customer.
4. **Signed bundles: reuse OPA's existing wire format** (gzip tarball + manifest, `.signatures.json` JWT signature over per-file hashes, keyid/scope verification, ETag-polling) — near-free since Damping already embeds OPA. Fix its two known weak points before shipping: (a) multiple named, rotatable verification keys with an overlap window instead of a single static keypair; (b) default to **Ed25519** rather than RSA (smaller/faster/deterministic, matters since the CLI fleet verifies on every poll, including constrained/offline hosts). Copy Styra DAS's operational safety net: immutable per-bundle versioning with retained history, automatic vs. approval-gated distribution, and one-button rollback to last-known-good — because a bad fleet-wide policy push for a tool that blocks-or-allows shell commands is a P0 incident, and no surveyed vendor ships enterprise policy distribution without a rollback story.

Explicitly **do not** copy GitLab's all-in-one license-gated monolith (too much surface for a small team to maintain right now) or HashiCorp's fully-proprietary-Enterprise-gate applied to the *core policy engine* (Damping's value proposition depends on the enforcement path being inspectable/trustable more than Vault's storage engine does — the gate belongs on the control plane, not the engine).

### Caveats

Styra DAS docs pages returned DNS failures during direct fetch in this research pass (likely transient/network-level, not evidence the claims are wrong) — corroborated across multiple independent search snippets, medium-high confidence but not directly quoted from source. Pricing figures (GitLab, Infisical, etc.) came from third-party aggregators, not vendor pages directly — directional only. This is a genuinely new product category (no vendor does exactly "intercept and evaluate AI-agent tool calls, enterprise fleet-managed") — the recommendation is reasoned by analogy from adjacent categories, not from a same-category precedent; revisit if a direct competitor's architecture becomes visible. This research does not re-litigate the broader open-core monetization strategy itself, only the licensing-boundary shape within it — that decision should still get informed by actual customer conversations.

---

## 5. Phase 6 — Memory & Context Poisoning Defense: Draft Spec

**Grounded in the actual repo** (`core/event`, `core/decision`, `core/policy`, `core/audit`, `cli/cmd/hook.go`, `cli/adapter/mcp`), not the threat-model doc alone.

### Headline finding: two separable problems, only one fits Damping's existing model

1. **Write-time gating** — solvable, extends the existing model additively.
2. **Retrieval/context-assembly-time correlation** (the real GoPlus "remember a preference now, handle it as usual weeks later" pattern) — **not solvable** by any write-time control, because by the time the dangerous later action reaches Damping's hook, Damping has no visibility into which memory entries the agent pulled into context to justify it. Neither Claude Code's nor Cursor's hook protocol discloses "what context informed this call." This can only be *approximated* via session/time-proximity correlation, never solved causally, without upstream agent-vendor protocol cooperation Damping doesn't control.

### The concrete prerequisite, more urgent than the scoring model itself

`cli/cmd/hook.go` line 96 currently does `if in.ToolName != "Bash" { return nil }` — Damping today observes **only** Bash tool calls. It never sees `Edit`/`Write`/`MultiEdit`, which is exactly how CLAUDE.md / `.cursor/rules` (real individual-tier "memory") get written. **Scoring a write Damping never observes is moot — widening this filter is Phase 6 step 1, before any trust-scoring code.**

### Schema changes (all additive — no existing field changes shape)

- `core/policy/policy.go`: `Facts` gains an optional `Memory *MemoryWriteFacts` sub-struct (store, scope, content hash/diff-vs-prior, source channel, provenance chain, trust score/factors, matched signature) — only set when `ActionType == event.ActionMemoryWrite`.
- `core/decision/decision.go`: `Decision` gains optional `TrustScore`, `TrustFactors`, `ReviewRequired`, `RelatedEventIDs` — **`Verdict` enum stays Allow/Deny/Prompt, unchanged.**
- `core/policy/config.go`: new `Config.MemoryGuard` section (trust weights per source channel, known-poison signatures, trigger phrases, sensitive-action verbs, review/deny thresholds, memory-store paths) — follows the existing `ProtectedPaths`/`AllowlistedInstallDomains` pattern.
- `cli/cmd/hook.go`: widen the tool-name filter to classify `Edit`/`Write`/`MultiEdit`/`NotebookEdit` writes to known memory-store paths as `event.ActionMemoryWrite`.
- `cli/adapter/mcp/facts.go`: new memory-tool recognition heuristic (MCP has no standard memory-write annotation, unlike `DestructiveHint` — this is necessarily a maintained name/schema list, same caveat as the existing shell alias table).

### Detection approach (mapped to Damping's adapter-precomputes / Engine-stays-pure split)

1. **Provenance tagging at write time** (adapter-side) — source-channel classification + ordered provenance chain with static trust weights. Zero new dependencies; industry-converged first layer (OWASP Agent Memory Guard, NeuralTrust, mem0.ai).
2. **Composite trust scoring** (adapter-side, deterministic weighted sum — **not ML for V1**) — explainable, consistent with every existing matcher being a pure testable predicate.
3. **Memory diffing** (adapter-side + small new state store, e.g. `~/.damping/memory_state.jsonl`) — cheap lexical similarity (token-set Jaccard/trigram) against prior value; no embeddings needed.
4. **Known-poisoned-content signature cross-referencing** — same mechanism as existing `AlwaysAllow`/`AlwaysDeny` glob matching, extended to a maintained signature list (MINJA/AgentPoison/PoisonedRAG-derived); same trust/maintenance model as antivirus definitions.
5. **Structural/imperative-instruction pattern detection** (pure regex/keyword co-occurrence) — modeled directly on the real GoPlus incident: a trigger phrase ("as usual," "by default," "next time") co-occurring with a sensitive-action verb (transfer, delete, grant, approve...). Structurally identical to the existing `destructive.encoded_payload_pipe` shape-matching idea.
6. **Behavioral/anomaly monitoring** — out of scope for a single `Evaluate()` call; would need a new periodic-job component (shape of `damping doctor`'s stateful comparison), not a matcher.
7. **Human-in-the-loop review, three-tier:** exact signature match → `Deny` (existing UX); high-confidence structural match → `Prompt` (existing synchronous flow); ambiguous middle → `Allow` **plus** `ReviewRequired: true`, surfaced asynchronously — because blocking every medium-confidence write would recreate the "nagging → uninstalled" failure mode `mcp.write_tool_unscoped_identity` was deliberately kept out of `default.yaml` to avoid.

### Policy rule sketch

New `core/policy/rules_memory.go` registered in the existing `matchers` map:

```go
"memory.write_known_poison_signature":  matchMemoryKnownPoisonSignature,  // -> deny
"memory.write_imperative_trigger":      matchMemoryImperativeTriggerPattern, // -> prompt
"memory.write_low_trust_score":         matchMemoryLowTrustScore,         // -> Review-only, NOT allow/deny/prompt
```

The third rule doesn't fit `RuleConfig{Action}` cleanly — its intent is "let it through but flag for async review," a different axis from `Action ∈ {allow, deny, prompt}`. Recommend a small additive `RuleConfig.Review bool` field (default false); when a matched rule has `Review: true`, `Engine.Evaluate` keeps `Action` as declared but also sets `Decision.ReviewRequired = true`. One extra line in the existing first-match-wins loop, not a redesign. Numeric threshold and string-set-membership checks both port to Rego without issue — extend `policy.rego` and the OPA equivalence-test fixtures the same way every existing rule already has fixtures.

### Open questions, ranked by fundamentality (not ease of fixing)

1. **Retrieval/context-assembly gap is unsolvable unilaterally.** Best available mitigation — correlating a recently-flagged `memory_write` with a later high-risk action in the same `SessionID` via `Decision.RelatedEventIDs` — is heuristic, not proof. Worth raising with Anthropic/Cursor as a hook-protocol feature request.
2. **`ReviewRequired` implies new UX Damping doesn't have** — `cli/dashboard` is today explicitly read-only. A review-queue acknowledge/resolve workflow is closer in shape to Phase 4's team dashboard than anything local-only, raising a sequencing question: should this wait for Phase 4 rather than being built twice.
3. **The Bash-only filter fix may be insufficient alone** — unverified whether Cursor's hook contract exposes any file-edit interception point at all; if not, Phase 6 ships asymmetric coverage that needs documenting as loudly as the existing shell-alias gaps.
4. **Embedding/ML dependency tension is a product-identity question**, not just implementation detail — Damping's whole value prop is zero-extra-dependency, sub-100ns, fully-offline evaluation. Ship only the lexical/structural/signature proxy for V1; treat true embedding-based drift detection as an optional plugin (mirroring the existing `Evaluator` interface), never a default-on dependency, and note that a cloud embedding API would itself introduce a data-exfiltration surface — ironic for a security tool — warranting explicit sign-off from Tim, not a unilateral engineering call.
5. **Signature-list curation has no owner yet** — frozen-in-binary goes stale; live-fetched reintroduces a supply-chain trust question structurally identical to antivirus/threat-intel feeds. Needs a decision before `default.yaml` ships any non-empty list.
6. **False-positive risk is likely the dominant product risk here, more than for shell rules** — natural language is far more ambiguous than shell syntax ("as usual, run the linter" is innocuous). Consistent with the project's "false positives are enemy #1" principle and the precedent of keeping `mcp.write_tool_unscoped_identity` out of defaults: **ship all `memory.*` rules non-default/opt-in (or Review-only, never Deny/Prompt by default) until real false-positive rates are measured.**

---

## 6. Where Self-Hosting Is — and Isn't — the Right Call

Tim's instinct toward self-hosted infrastructure is genuinely well-supported by this research, but not uniformly — and the pattern across all four findings is consistent enough to state as a rule of thumb:

**Self-hosting is the right call when the system in question *is* (or directly protects) Damping's core security claim** — the code the team needs to be able to read, patch, and have customers trust without a third-party intermediary:

- **Phase 3:** The OAuth token-issuance/audience-binding engine — the literal mechanism the confused-deputy defense rests on. Ory Hydra/Fosite, self-hosted and Go-native, wins over Keycloak or a pure vendor precisely because the team can own this logic.
- **Phase 5:** The policy engine and enforcement path (`core/`, `cli/`) stay open and self-hostable/inspectable forever — non-negotiable, because a tool that intercepts every shell command before execution has to be auditable to earn trust from the exact security-conscious buyers Damping is courting. The regulated/air-gapped segment (defense, banks, government) categorically requires this, and every mature comparable (GitLab Dedicated, Teleport self-hosted HA, Vault Enterprise self-managed) confirms it's not optional at the top of the market.
- **Phase 4:** The core policy engine, audit data, and infrastructure Damping actually differentiates on stay self-hosted-friendly; only the SSO federation layer is carved out (below).

**Self-hosting is the wrong call — or at least a poor use of a small team's time — when the problem is a long-tail integration/support burden with third-party systems Damping doesn't control**, rather than a "run software you own" problem:

- **Phase 4's enterprise SSO/SAML integration** is the clearest case. Supporting Okta, Entra/Azure AD, ADFS, Google Workspace, PingFederate, and OneLogin — all nominally "SAML 2.0," all with real quirks — is a problem that *grows* with every new enterprise customer, not a fixed one-time build. Certificate rotation on 1–3 year cycles is cited as one of the most common ways enterprise SSO breaks in production; that's ongoing maintenance risk with no natural end-state, categorically different from operating a Go binary the team fully understands. The self-hosted alternatives make the case for buying, if anything, more strongly than the vendor pitch does: Keycloak solves SAML but at a genuinely mismatched Java/ops cost for a security product; Ory's OSS core doesn't solve SAML at all, so self-hosting it for real enterprise coverage means either running an under-vetted extra component or paying Ory's own SaaS tier anyway — quietly conceding the argument while losing the cost advantage. WorkOS AuthKit is free until it's needed, scales cost with the enterprise revenue that triggered the need, and removes Damping engineers from every onboarding call.
- **Phase 3's enterprise SSO front-door** is the same shape of exception, for the same reason: federating into a customer's own IdP is commodity plumbing that doesn't differentiate Damping, even though the core token-exchange engine sitting behind it does.

**The one deliberately open item, not yet settled either way:** signature-list curation for memory-poisoning defense (Phase 6) has the same "who maintains this against a moving adversary" shape as the SSO problem, but the research didn't reach a recommendation — it flags this as needing an explicit decision (frozen-in-binary vs. live-fetched-with-a-trust-model) before any non-empty list ships, precisely because it could go either way depending on how much ongoing curation effort Damping wants to own versus outsource.

**Net assessment:** the instinct to self-host is correct wherever the software *is* the security promise being sold, and it should be applied without compromise there even at real operational cost (this is where the Keycloak TCO numbers and Cloudflare incident history matter — they're arguments for *choosing carefully within* self-hosting, e.g. Hydra over Keycloak, not arguments against self-hosting itself). The instinct is a poor fit specifically for enterprise identity-federation plumbing, where the risk isn't operational control but an ever-growing, low-differentiation integration surface — and there the evidence points consistently, across two independent research passes (Phase 3 and Phase 4), toward buying a purpose-built SSO-as-a-service layer (WorkOS) rather than building or self-hosting one.
