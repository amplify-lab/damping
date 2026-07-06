# Damping Enterprise Architecture — Round 3 Final Synthesis

*Third and final research pass. Round 1 proposed; round 2 independently verified and reversed/amended three of four phases; round 3 adversarially stress-tested round 2's own new claims, gave Skills the same rigor the other topics got, and completed the CodeIntegrity competitive deep-dive round 2 flagged but didn't do. This document is the decisive final call — where to act, where to keep researching (nowhere, per §7), and where to just decide.*

---

## 1. Executive Summary

| # | Topic | Round 2 recommendation | Round 3 final call | Tag |
|---|-------|------------------------|---------------------|-----|
| 3a | OAuth provider for token-issuance/audience-binding engine | Abandon self-hosted Ory Hydra default; **trial Authlete as primary path** (only vendor with joint RFC 8707+8693, has self-host license) | Do **not** commit to Authlete as primary path. Its closed-source engine contradicts Damping's own "auditable, self-hostable enforcement core" positioning even in the "self-managed" tier; the self-host pricing is sales-quote-only (same opacity round 1 warned about); zero independent evidence anyone uses it for MCP/agents; customer base is entirely Japanese. Treat as **one candidate among several to spike in parallel** (Ory Hydra Enterprise pricing, Keycloak's free RFC 8693 + in-progress RFC 8707, WorkOS's existing RFC 8707 support) — no vendor commitment yet. | **Round 2 was wrong, new call is X** |
| 3b | MCP Enterprise-Managed Authorization (EMA) / ID-JAG | Flag as "genuinely new, must be spiked before locking Phase 3/4" | Fully confirmed via primary sources: stable June 18 2026 (official MCP blog + GitHub "stable" folder), adopted by Okta (shipped, branded XAA), Anthropic (shipped, beta, own help docs), Microsoft (shipped at VS Code product level), real IETF WG draft. This should gate Phase 3 architecture — don't lock a full OAuth-AS build before spiking ID-JAG interop. | **CONFIRMED from round 2** |
| 4 | Ory Polis (BoxyHQ Jackson) for self-hosted SAML | Free, mature, actively maintained, covers Okta/Entra/ADFS/OneLogin/PingOne/Google/JumpCloud, beats paying Ory's enterprise tier | Core claim holds (Apache-2.0, no per-IdP paywall, maintainer-confirmed multi-tenant SSO/SCIM free). But "mature/battle-tested" is oversold: maintainers admit free-tier releases now ship only "a few times a year," a security-adjacent SAML fix sat unreleased 3+ months, and Ory openly upsells its paid tier using release speed as the lever. Only one cited user (Formbricks) is a real confirmed production dependency; the other three are ecosystem/marketplace availability, not evidence of internal use. | **REVISED from round 2** |
| 5 | Build SaaS-only first; defer self-hosted mode until demand | SaaS-first, cite Styra/GitLab/Documenso as proof this sequencing works | Round 2's own comparables contradict its conclusion: Documenso never deferred self-hosting (only a paid *enterprise support* SKU came ~2 years later); GitLab shipped self-hosted CE **three years before** SaaS existed — the reverse pattern. A modern counterexample (Infisical) shipped both day one and thrived. On-prem is a hard procurement gate for regulated buyers, not an upgradeable-later preference. Damping's CLI already executes locally by necessity. CodeIntegrity is right now using self-host as its live pitch to the exact buyers round 2 said to wait for. New call: **ship a basic free self-hosted mode alongside hosted from early on; defer only the expensive parts** (enterprise SLA/support, compliance certs, multi-tenant fleet-management control plane) until paying demand justifies them. | **Round 2 was wrong, new call is X** |
| 6 | Build `event.ActionSkillInvoke` + correlation engine now; widen hook.go globs to skills dirs; declare dynamic-context-injection and cloud-sync skills categorically unsolvable (documentation-only) | Full Skills defense package, built now | Splits cleanly. **Glob-widening survives** (cheap, rides the CLAUDE.md PR, covers a real gap — bare/non-plugin skills get zero Anthropic-native trust friction). **New event type + correlation engine does not survive** — no confirmed real-world victim incident exists (every dramatic exploit is an explicitly-labeled lab/red-team demo), the payload shape isn't even confirmed buildable, and round 2 flagged its own elevated false-positive risk — this is the same "build ahead of demand" mistake round 2 accused round 1 of, applied inconsistently in round 2's own document. The "categorically unsolvable" framing for dynamic-context injection is wrong — Anthropic already ships a beta sandbox (filesystem+network isolation) round 2 missed, which would defeat the cited exploit. Two of round 2's four supporting factual claims also need correction (see §5/§6 below). | **REVISED from round 2** |

---

## 2. Phase 3 Final Verdict — OAuth Provider Choice + MCP EMA/ID-JAG

### 3a. Authlete: real vendor, oversold recommendation

Round 3 fetched Authlete's own docs, pricing page, and customer case studies directly. The facts round 2 cited are mostly real:

- **RFC 8693 support is genuine**, with an actual worked curl/JSON example in Authlete's developer docs — not marketing copy.
- **RFC 8707 is a real, documented parameter** on the same token-exchange endpoint, so the two specs are *technically composable*.
- **Self-hosting is real and proven** — Seven & i Holdings (85,000+ store retail group) runs Authlete on-prem in their own datacenter for exactly the reason Tim would care about ("on-premises option was an essential requirement").

But the recommendation itself does not survive adversarial pressure, for one dominant reason and several supporting ones:

1. **Direct contradiction of Damping's own stated principle.** Round 1's text explicitly says the audience-bound-token engine is "the literal mechanism the confused-deputy defense claim rests on" and must be self-hostable/auditable because security-paranoid buyers won't trust an opaque vendor's token-issuance logic. Authlete's core decision engine is closed-source and API-gated **even in its self-managed/on-prem tier** — only the endpoint wrapper is yours; the actual authorization logic remains undisclosed IP reached via API. Round 2 applied this exact inspectability test to reject Ory for Phase 4 but never applied it to Authlete here — an internal inconsistency round 3 caught.
2. **The tier that matters has no public price.** Only the Business/Shared-Cloud tier is self-serve ($999+/mo); both Enterprise (Managed Cloud) and Enterprise (Self-Managed) — the deployment mode round 2 recommended — are sales-quote-only. Same opacity pattern round 1 already flagged as a reason to avoid other vendors.
3. **No independent MCP validation exists anywhere.** Zero Hacker News threads, zero Reddit discussion, G2 review page inaccessible. Even Authlete's own Feb 2026 MCP announcement (Authlete 3.0/CIMD) cites RFC 8707 for MCP but **never mentions RFC 8693 (token exchange)** in that context — Authlete itself isn't making the "token-exchange for MCP" claim round 2 built the recommendation around.
4. **Go-to-market fit risk.** Every verifiable enterprise reference (Minna Bank, NRI SecureTechnologies, Seven & i) is Japanese; funding ($7.88M) is almost entirely from Japanese investors (NTT Docomo Ventures, Toppan, SBI, MTI). No US enterprise reference surfaced for a US-based buyer.
5. **A free alternative is closing the same gap.** Keycloak shipped standards-compliant RFC 8693 in v26.2 (May 2025) and has an open, in-progress RFC 8707 implementation (tracked GitHub issue #14355 / PR #35711) specifically for MCP compatibility — for $0, Apache-2.0, Red Hat-backed. Round 2 rejected Keycloak only on ops-burden grounds, never re-scored it on capability.
6. **Unresolved overlap with a vendor already being bought.** Round 2's own text admits WorkOS (already committed to for Phase 4 SSO) "already independently supports RFC 8707 for MCP" and flags this overlap as unresolved — recommending a second, closed-source, foreign vendor before resolving that is adding vendor risk, not reducing it.

**Final call:** Downgrade Authlete from "trial as primary path" to "one candidate to spike in parallel," alongside pricing out Ory Hydra Enterprise, re-scoring Keycloak now that it ships free token exchange, and clarifying WorkOS's own roadmap — before any commercial or architectural commitment. Treat the inspectability contradiction as a disclosed tradeoff to raise with Tim explicitly, not something to gloss over.

### 3b. MCP EMA / ID-JAG: holds up completely

This is the one round-2 claim that survived round 3's scrutiny essentially unscathed. Verified directly from primary sources:
- **Stable June 18, 2026** — confirmed verbatim in the official MCP blog (named core maintainer Paul Carleton) and structurally corroborated by the spec repo's `stable/` folder path.
- **Okta**: shipped, self-branded as "Cross App Access (XAA)," confirmed via Okta's own developer blog.
- **Anthropic**: shipped in beta, confirmed via Anthropic's own help-center docs ("Enterprise-managed auth is available in beta for Team and Enterprise plans on Claude").
- **Microsoft**: confirmed at the product level (VS Code 1.123 shipped enterprise-managed MCP auth with Entra ID/Okta/Auth0 as supported IdPs) — not a standalone corporate statement, but a real shipped product.
- **ID-JAG's IETF pedigree**: confirmed real WG-adopted draft (`draft-ietf-oauth-identity-assertion-authz-grant`), though the exact adoption month claimed by secondary sources couldn't be pinned to a primary datatracker diff.

**Final call:** This is real and moving fast. It should gate the Phase 3 spike — don't lock a full self-hosted-or-buy OAuth-AS architecture before testing whether Damping can instead interoperate with a customer's own IdP via ID-JAG, which could make part of the AS build/buy question moot for the enterprise segment.

---

## 3. Phase 4 Final Verdict — Ory Polis

Round 3 pulled Ory Polis's GitHub data directly (via `gh api`), read maintainer discussions verbatim, and cross-checked all four cited production users.

**What holds:** License is genuinely Apache-2.0. Core SAML/OIDC bridge against the named IdP list (Okta, Entra, ADFS, OneLogin, PingOne, Google, JumpCloud) works today, free, with no per-IdP paywall — maintainer-confirmed directly, including multi-tenant SSO/SCIM. It is **not abandoned** — original BoxyHQ engineers still personally respond on GitHub through 2026, commits continue weekly.

**What needed correction:**
- Ory's own maintainers say **on the record** (Oct 2025 GitHub discussion) that free-tier releases now ship only "a few times per year, no fixed schedule" — and an Ory team member explicitly pitches the paid Enterprise License because it gets "hardened, weekly releases." Ory is using release cadence as a monetization lever against its own free-tier users.
- A **concrete, dated instance**: a SAML-signing-related fix committed April 3, 2026 was still unreleased to OSS users as of June 27, 2026 — a 3+ month lag on a correctness/security-adjacent fix. This is a stronger, more citable data point than a vague "cadence" claim.
- Ory's marketing page and its own maintainers **contradict each other** on exactly what's enterprise-gated — the maintainer says only branding/federation are paid; the marketing page implies broader SAML/OIDC/SCIM "enterprise features" are gated too. The free/paid boundary is not as clean as round 2 implied.
- Of the four cited production users, only **Formbricks** is a solid, currently-documented real dependency. NextAuth/Auth.js and the Bubble plugin are ecosystem/marketplace compatibility, not confirmed internal use; the Cerbos citation is a demo repo, not a case study.
- Ory moved to a monorepo (Dec 2025) — an unresolved forward-looking risk to Polis's standalone maintenance visibility.

**Final call:** Ory Polis remains the right default — free, real, beats paying Ory's enterprise tier just to get basic SAML. But ship this into Phase 4 messaging with **hedged language**, not "mature/battle-tested." Treat the release-cadence lag as a live risk to monitor (not just a one-time research finding) if Damping ends up depending on it for timely SSO security patches, and budget for the possibility of eventually needing the paid OEL tier for support/cadence guarantees, not because the free code is deficient.

---

## 4. Phase 5 Final Verdict — SaaS-First Sequencing + CodeIntegrity

### Sequencing: round 2's own evidence contradicts its conclusion

This is the most significant reversal of round 3. Round 3 went back to round 2's own cited comparables and found they don't say what round 2 said they say:

- **Documenso** (round 2's flagship example): its free, self-hosted **community edition existed continuously from founding** — the Sept 2025 announcement added a **paid enterprise support/compliance license** ($30k/yr, SSO/audit/certs/support), not self-hosting capability itself. Self-hosting was never deferred. (Round 3 also found the license-gated `ee` code split existed in the codebase within ~7 months of founding — the open-core architecture was baked in almost from day one; only the go-to-market productization event came ~2 years later.)
- **GitLab**: self-hosted CE shipped in 2011; GitLab.com SaaS didn't exist until **2014** — the reverse of the pattern round 2 implied.
- **Counterexample round 2 didn't check for**: Infisical (YC W23, open-source secrets/PAM manager) shipped free self-hosted (MIT) and paid cloud **simultaneously** at public launch (Feb 2023) and has grown successfully since — direct evidence against "must sequence, can't do both at once."

Beyond the comparables being wrong, three structural arguments make SaaS-only actively risky for Damping specifically:

1. **On-prem is a hard procurement gate, not a soft preference.** Industry research shows roughly a third of enterprise buyers require air-gapped/on-prem procurement (defense/ITAR, government/FedRAMP, regulated industries) — these buyers self-select out before a sales conversation happens, meaning SaaS-only doesn't just delay reaching them, it can permanently prevent Damping from ever observing the demand signal round 2 said to wait for.
2. **Damping's architecture is different from Documenso/GitLab's.** Damping's CLI+MCP adapter already executes locally by necessity (real-time shell/tool-call interception can't route synchronously through a third-party cloud for the exact security-conscious buyers it targets). Self-hosted mode is close to the product's natural default, not an expensive bolt-on the way it is for a multi-tenant hosted web app.
3. **A live competitor is exploiting exactly this gap right now** (see CodeIntegrity below) — using self-host as its present-tense pitch to regulated buyers, at an earlier company stage than Damping.

**Final call:** Ship a basic, free self-hosted mode alongside a hosted option from early on. Defer only the genuinely expensive, revenue-funded pieces — enterprise SLAs/support contracts, compliance certifications, and a multi-tenant SaaS fleet-management/dashboard control plane — until paying demand justifies them. This is closer to round 1's original hybrid instinct than round 2's reversal, but sharper: round 1 said "build both simultaneously" without specifying scope; round 3's corrected version specifies exactly what ships now (basic self-host + basic hosted) versus what waits (the expensive enterprise layer).

### CodeIntegrity deep-dive: real threat, moderate near-term risk, actionable signal

The dedicated look round 2 flagged as needed was completed. Findings:

- **Real and credibly funded**: $5M seed (May 2026, led by Syn Ventures, a security-focused VC), founders with public exploit-research credibility (Notion/Linear/Shopify/Neon/Azure/Heroku prompt-injection write-ups, an Economist mention).
- **Real overlap on one axis**: "Memory Poisoning" is one of its five named flagship risk categories — directly validating that Damping's Phase 6 direction (hook.go widening into memory-file writes / Skills) is on the right track, independent of anyone else's opinion.
- **But it's pre-launch/pilot-stage, not GA**: no named customers, no public pricing (pricing page 404s, book-a-demo only), no review-platform presence at all, several product pages 404 or are gated — piloting with unnamed "companies in regulated industries," broader rollout still "planned" as of the announcement.
- **Different buyer/niche**: its GTM and research target enterprise-SaaS-embedded agents (Notion, Linear, Shopify) for security/GRC teams governing agent sprawl — not developer-facing coding-agent CLIs, which is Damping's actual niche. No overlap in named comparables (Damping/dcg/Aegis/Pipelock don't appear in CodeIntegrity's materials or vice versa).
- **Its deployment story is ambiguous, not a settled two-tier model** — "runs inside your own environment when needed" reads as negotiated-per-deal at this stage, not a mature open-core product line. This means CodeIntegrity is too early to serve as sequencing evidence either way — it neither confirms nor contradicts the corrected Phase 5 call above.
- A wider cluster is forming: three other similarly-aged, funded 2026 entrants (Certiv, Raven, Manifold Security) exist in adjacent territory, none of which appear in Damping's own comparisons either.

**Final call:** CodeIntegrity meaningfully erodes any claim that Damping is alone in this space, and its self-host-first pitch is itself supporting evidence for the corrected Phase 5 call above — but it is not yet a company whose product, pricing, or GTM Damping needs to react to tactically. The one concrete, actionable takeaway: treat its public "Memory Poisoning" framing as external validation to prioritize and ship Phase 6 sooner, and sharpen Damping's comparison-table positioning around developer/CLI-first (vs. CodeIntegrity's enterprise-SaaS-agent-governance framing) so the two aren't conflated by prospects.

---

## 5. Phase 6 Final Verdict — Skills Defense

Round 3 gave Skills the same two-pass rigor (fact re-verification + adversarial stress-test of the recommendation) the other phases got in round 2. Both passes produced corrections.

### Fact re-verification (4 claims, primary sources pulled directly)

| Claim | Round 3 status | What changed |
|---|---|---|
| Datadog `gh auth token` dynamic-context PoC executes before model refusal; `disableSkillShellExecution` is the only mitigation | **Confirmed** | Verified in full against Datadog's own May 2026 article; real in-the-wild malicious skill, real mechanism, no newer mitigation found beyond the kill-switch. One nuance preserved: Claude's baseline model review *does* catch the non-dynamic-context version — the bypass is an escalation on top of a working defense, not proof the defense never works. |
| Cloud-synced Skills inject with zero user control, "confirmed via a maintainer-closed GitHub issue" | **Revised** | The underlying bug report is real, detailed, and unrebutted — but it was closed by `github-actions[bot]` as stale/`not_planned`, not by a human Anthropic maintainer. No Anthropic employee ever commented. The same repo auto-stale-closes ~98% of unassigned open issues regardless of merit. Downgrade to "credible, unaddressed first-party report, auto-closed as stale — not officially acknowledged or fixed." |
| Cursor v2.4 and Codex both adopted agentskills.io, cross-loading `.claude/skills/` | **Revised** | agentskills.io is real (Anthropic-originated, Dec 2025) and Cursor v2.4 does cross-load `.claude/skills/` (confirmed via Cursor's own docs). But Codex, per OpenAI's own docs, **only** reads `.agents/skills/` — it does not read `.claude/skills/`. Round 2 wrongly extended Cursor's behavior to Codex. |
| PromptArmor found skill-scoped hooks (SKILL.md frontmatter) rewriting Claude Code's permission settings | **Revised** | The permission-rewrite mechanism is real and PromptArmor did publish it — but their actual article is entirely about **Plugin**-delivered hooks, not Skill-frontmatter hooks. Full-text search of the downloaded article found zero mentions of "SKILL.md," "frontmatter," or "hooks.json." This is plausible extrapolation, not a confirmed finding — flag as unverified until someone demonstrates the Skill-frontmatter variant specifically. |

### Adversarial stress-test of the recommendation itself

The core recommendation (build `ActionSkillInvoke` + a correlation engine now; widen hook.go globs; declare two defenses categorically unsolvable) **splits**:

- **Survives — ship now**: glob-widening hook.go to cover `.claude/skills/**`, `.cursor/skills/**`, `.agents/skills/**`, plugin skill dirs, and *every file* under them (not just SKILL.md). This is cheap, rides the same PR already committed to for CLAUDE.md widening, and fills a real gap: bare (non-plugin-wrapped) skills — the common case — get **zero** Anthropic-native workspace-trust-dialog friction on self-granted broad tool access, and native `Skill(name)` denylisting can't catch a newly-poisoned skill an org doesn't yet know is bad.
- **Does not survive — defer**: building `event.ActionSkillInvoke` and a new `RelatedEventIDs` correlation engine now. No confirmed real-world victim incident exists anywhere — every dramatic Skills exploit found (Datadog, Cato CTRL, Reversec, Pentera) is explicitly self-labeled as a controlled lab/red-team demonstration on synthetic infrastructure, not a documented breach. Independent scans (Snyk's ToxicSkills: 76/3,984 malicious; an academic study: 157/98,380, 0.16%) confirm malicious skill *artifacts* exist but don't establish real victims. Round 2's own text admits the payload shape "needs empirical confirmation" and that false-positive risk is "plausibly higher" for this feature than for memory-file writes — building it now repeats the exact "infrastructure ahead of validated demand" mistake round 2 accused round 1 of making in Phase 5, applied inconsistently within round 2's own document.
- **Missed mitigation**: Anthropic already ships a beta sandbox runtime (bubblewrap/seatbelt) with real filesystem *and network* isolation, explicitly designed to sandbox "arbitrary processes, agents and MCP servers." Network isolation directly defeats the exact exfiltration mechanic in Datadog's PoC (`gh auth token` + curl to attacker infra), regardless of when the shell command executes relative to any hook. Round 2's "dynamic-context-injection is categorically unsolvable, documentation-only" framing is wrong — there's a second, more complete, already-shipped control it missed.
- One case study attributed to Skills (an academic paper linking Anthropic's Nov 2025 GTG-1002 state-actor disclosure to "a benign-looking skill installing a backdoor") does not hold up — Anthropic's own primary disclosure and every corroborating outlet describe a different mechanism (a state actor directly operating a jailbroken Claude Code instance via MCP tool weaponization), not a Skill-based compromise. This citation should not be used.

**Final call:** Ship the glob-widening now, in the same PR as the CLAUDE.md work. Do not build `ActionSkillInvoke` yet — convert it to a backlog item gated on either a real customer-reported incident or a cheap live-session BDD spike confirming the tool_input payload shape. Update `damping doctor` to check for and recommend Anthropic's own native, free mitigations first: `disableSkillShellExecution`, the beta sandbox runtime, and `Skill(name)` denylisting — these are already-shipped and, for the sandbox specifically, strictly more powerful against the pre-hook dynamic-context gap than anything Damping's hook architecture alone can offer. Reword "categorically unsolvable" to "unsolvable by Damping's hook architecture alone, partially mitigated by Anthropic's own opt-in sandbox — verify it's enabled via `damping doctor`."

---

## 6. What Round 2 Got Wrong or Oversold — Honest Accounting

Round 2's *facts* were, almost without exception, real — every primary source it cited checked out when round 3 went and fetched it directly. Round 2's failure mode was consistent and specific: **it took a favorable reading of a real fact and stretched it slightly further than the fact supports**, and it didn't apply its own newly-established standards (demand-validation, inspectability) to its own new recommendations.

- **Phase 3**: Oversold "Authlete ships joint RFC 8707+8693 out of the box for MCP" — no such joint example exists anywhere in Authlete's docs, and Authlete's own MCP announcement doesn't even mention token exchange. Oversold self-host accessibility — the tier that matters has no public price, same opacity round 1 flagged elsewhere. Applied the inspectability principle to reject Ory in Phase 4 but not to Authlete in Phase 3 — an internal double standard. Missed Keycloak's free RFC 8693 support entirely.
- **Phase 4**: Oversold Ory Polis's maturity — missed the maintainer's own on-the-record admission of slowed release cadence and Ory's explicit paid-tier-via-speed upsell. Overstated four production case studies when only one (Formbricks) is a real confirmed dependency.
- **Phase 5**: The most significant miss. Its own headline comparables (Documenso, GitLab) don't actually support the conclusion drawn from them — a case of reading a vendor blog's *date* without reading what the blog post actually said had changed. This is the one place round 3 found round 2 was not just optimistic but backwards on its own evidence.
- **Phase 6**: "Confirmed via a maintainer-closed GitHub issue" was a bot-closed-stale issue with zero human Anthropic engagement — a citation-strength error, not a factual one (the underlying report is still credible). Conflated Cursor's broader compatibility behavior with Codex's narrower one. Conflated a PromptArmor finding about Plugin hooks with an extrapolated claim about Skill-frontmatter hooks. Missed Anthropic's own sandbox mitigation. And recommended building new infrastructure ahead of validated demand — the exact mistake it caught round 1 making in Phase 5, applied inconsistently in its own Phase 6.

The throughline: round 2 was a good adversarial pass against round 1, but it didn't turn that same adversarial lens on itself. Round 3's main value wasn't finding new facts round 2 missed (though it found a few — Keycloak, the Anthropic sandbox, GitLab's reverse sequencing) — it was catching round 2 not holding its own new recommendations to the standards it had just finished establishing.

---

## 7. Is Three Rounds Enough?

**Yes — stop researching this set of questions and start deciding.** What remains after three rounds of increasingly adversarial, primary-source-grounded research is no longer discoverable by more googling. It falls into three buckets, each of which needs a different kind of next step:

1. **Needs a vendor conversation, not a search query.** Authlete's actual self-host pricing, Ory Hydra Enterprise's actual pricing, and whether WorkOS's existing RFC 8707 support overlaps or composes with a separate token-exchange need are all locked behind sales-quote walls by design — no amount of further web research will surface a number a vendor hasn't published. This is 2-3 short calls, not a fourth research round.
2. **Needs a cheap live spike, not more reading.** The Skill `tool_input` payload shape (needed before `ActionSkillInvoke` could even be built) and the MCP EMA/ID-JAG interop shape (needed before Phase 3 architecture locks) are both things round 2 itself flagged as unconfirmed-by-research — they resolve with an afternoon of hands-on engineering, not another search pass.
3. **Needs a business/roadmap decision, not a fact.** Phase 5 is now a scoping question for Tim: the evidence is in (on-prem is a hard procurement gate; Damping's architecture already runs locally; a comparable-stage competitor is using self-host as its live pitch) — what's left is deciding how much of the "expensive" enterprise layer to build and when, which is a resourcing call, not a research question.
4. **Needs observation over time, not more searching now.** Ory Polis's release cadence and whether a real Skills-based victim incident ever materializes are both things to *watch*, not things a fourth round of research this month would resolve — they haven't happened yet to find.

A fourth round chasing these same four phases with more web searches would have sharply diminishing returns: the primary-source surface (vendor docs, pricing pages, GitHub issues/discussions, IETF datatracker, case studies, competitor sites) has now been read directly, not summarized secondhand, across all three rounds. The productive next step is the short list above — a few vendor calls, one or two cheap spikes, and one roadmap decision — not a round 4.
