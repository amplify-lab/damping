# Damping — Dashboard & Enterprise UI/UX Spec (Phase 4 & 5)

> Scope: the React + TypeScript dashboard (`dashboard/`, not yet scaffolded — see `docs/architecture.md` §1) that Phase 4 (team tier, Cloudflare Track A) and Phase 5 (enterprise compliance, Track B) build against. This is a structural/interaction spec, not implemented UI code — Phase 4 is months out per the roadmap in `docs/00-統一開發計畫（定案版）.md`, and speculative React code written now would likely be discarded once real usage data exists. What's fixed here (visual metaphor, screen inventory, states, information hierarchy) is meant to survive that gap.

## 1. Visual metaphor — make "damping" visible, not just named

The brand's whole thesis is "governance ≠ blocking; it's suppressing runaway oscillation back to a stable range" (`品牌與命名體系.md`). The dashboard should be the one place this metaphor becomes a literal, functional visual, not just copy:

- **The core recurring visual element is a damped oscillation waveform** — an amplitude that starts high and jagged (representing an ungoverned/risky agent session) and settles into a flat, steady line (representing a session under policy). This is not decoration; use it functionally:
  - **Per-session risk sparkline**: each active agent session gets a small waveform showing risk-level over time. A session with several high-risk interceptions that were denied/resolved shows a wave that spikes then flattens. A session still spiking is visually, immediately distinguishable from one that's settled.
  - **Loading/skeleton states** use a gently decaying waveform animation instead of a generic spinner — reinforces the brand at the micro-interaction level for near-zero extra cost.
  - **Empty states** show a perfectly flat line with a short caption ("No activity yet — nothing to dampen.").
- **Color system**: dark-mode-first (matches developer-tool convention and the target audience from the CLI ecosystem). Risk levels map to a temperature scale — critical/high = warm (red/amber), medium = yellow, low/allowed = cool (teal/blue) — and the damped-oscillation motif visually reinforces this: waveforms literally cool from red to blue as they settle, so color and shape tell the same story redundantly (accessibility win — not relying on color alone; see §6).
- **Wordmark**: "Damping" set in a monospace-adjacent technical typeface (consistent with the CLI/dev-tool audience), with the oscillation motif as an optional mark/favicon — a simple sine wave collapsing into a flat line.

## 2. Screen inventory — Phase 4 (Team Dashboard, Track A)

### 2.1 Sign-in
- SSO via WorkOS/Auth0/Stytch (per `營運計劃書.md` §十五 — team tier does not roll its own auth).
- No local password option — matches "don't build what a vendor already solved" discipline applied elsewhere in this project (Keycloak for enterprise, WorkOS-class for team).

### 2.2 Team overview (home)
- Top strip: today's interception count, active members (opted-in / total), highest-risk event in the last 24h.
- **Live event stream** (see §2.3) embedded as the dominant panel — this is the product's core value, it should not be buried behind a click.
- Right rail: per-member mini risk-sparklines (the damped-oscillation motif at a glance, per member).

### 2.3 Event stream
- Real-time table (WebSocket via Durable Objects Hibernation, per `營運計劃書.md` §十五): Time, Member, Channel (cli/mcp badge), Target, Risk, Decision.
- Filters: member, channel, risk, decision, time range — same filter vocabulary as `damping log` (§7 of `docs/cli-reference.md`), so a user who knows the CLI already knows the dashboard.
- Row click → detail drawer: full `ActionEvent` (raw command/call, parsed args, matched policy_id, resolution timeline for prompt→allow/deny cases).
- **Never a blank screen**: empty filter results show "No events matched these filters" (never silent blankness — same discipline as the CLI, see `docs/cli-reference.md` §7).

### 2.4 Policy editor
- Rule list view mirrors `damping policy list` (id, description, risk, action) — read consistency between CLI and dashboard is a deliberate choice, not an accident.
- Edit mode: form-based editor for common fields (risk tier, action, protected paths, allowlisted domains) for non-YAML-comfortable users, with a "view raw YAML" toggle for those who prefer it (mirrors `damping policy edit` opening a raw file for CLI users).
- "Publish to team" button — explicit push action, versioned (simple diff view: what changed since the last published version), because policy changes affecting a whole team should never be silently live.
- Every opted-in member's local Damping install continues to treat its own `~/.damping/audit.jsonl` as the local source of truth (see `features/team_dashboard.feature`) — the dashboard pushes policy down, it does not become the audit system of record for a member's own machine.

### 2.5 Member management
- List: member, opt-in status (opted-in / not opted-in — never inferred, always the member's own explicit `damping sync enable` state), last-seen, event count (7d).
- No control here can pull a non-opted-in member's data — this is a hard boundary, not a permission setting an admin can override, per `features/team_dashboard.feature` and the "team opt-in must be explicit" principle carried through every planning doc.

### 2.6 Alerts configuration
- Slack webhook setup, threshold rules (e.g. "N high-risk denials in T minutes → alert"), per-channel routing (route MCP alerts differently from CLI alerts if desired).
- Alert payload links directly to the relevant event(s) in the dashboard — no alert should require manually hunting through the event stream to find what triggered it.

### 2.7 States that must exist for every data-bearing screen
- **Loading**: damped-waveform skeleton (§1), never an indefinite spinner with no content shape.
- **Empty**: flat-line motif + one-sentence explanation of why it's empty and what would populate it.
- **Error** (storage API failure — D1/DO/R2 per `營運計劃書.md` §4.3): explicit "reconnecting" or "couldn't load" state with a manual retry/reset action — never a silently stale view that looks current but isn't.

## 3. Screen inventory — Phase 5 (Enterprise Compliance, Track B)

### 3.1 Compliance report generator
- Date range picker + format selector (initially: 金管會 format, AI基本法 format — see `營運計劃書.md` §三 item 5).
- Preview pane before export (a security officer should be able to see what they're about to hand to a regulator before committing to the export).
- Export produces the report **and** logs its own generation as an audit event (report generation is itself a sensitive, auditable action).
- Every high-risk action in the report shows actor, bound identity, channel, timestamp, decision, and full resolution outcome — the exact fields specified in `features/compliance_report.feature`.

### 3.2 RBAC policy management
- Role ↔ tool-permission matrix (rows = enterprise roles inherited from AD/LDAP, columns = MCP tools/CLI action categories, cells = allow/deny/prompt).
- Changes here are versioned and themselves audit-logged — RBAC policy edits are exactly the kind of action a bank's own auditors will ask about later.

### 3.3 Identity binding status
- Shows AD/LDAP sync health (last sync time, any identities that failed to bind), because "every action traces back to a real person" (the core Phase 5 promise) breaks silently if sync quietly stops working — this view exists specifically so it doesn't stay silent.

### 3.4 Immutability proof surface
- A visible, explicit UI element (not just a backend guarantee) showing the append-only constraint is active — e.g., an attempted edit/delete on any audit record surfaces a clear "audit records cannot be modified — this is enforced at the database level" message rather than a generic permission-denied error. This is a deliberate trust-building UI choice for skeptical bank security reviewers, not a technical necessity.

## 4. Cross-cutting interaction principles

1. **CLI/dashboard vocabulary parity**: filters, field names, and rule IDs are identical between `damping log`/`damping policy` output and their dashboard equivalents. A user who learns one interface has already learned the other.
2. **Never silently drop data**: every failure mode (storage API error, sync failure, identity-binding failure) gets an explicit, visible state — this mirrors the CLI's `degraded` audit principle (`docs/threat-model.md` §6) at the UI layer.
3. **Opt-in boundaries are structural, not cosmetic**: non-opted-in member data has no code path that surfaces it in the dashboard, not merely a UI element that's hidden.
4. **The oscillation motif is functional, not decorative**: if a component doesn't naturally map to "risk settling over time," don't force the metaphor onto it — overuse would cheapen the one place (per-session/per-member risk visualization) where it's genuinely informative.

## 5. Responsive behavior

- Primary usage is desktop (security/ops dashboards are not typically mobile-first workflows), but the event stream and alerts views should degrade to a single-column, card-based layout below ~768px so an on-call admin can check status from a phone during an incident.
- Wide tables (event stream, RBAC matrix) scroll horizontally within their own container rather than forcing the page to scroll sideways.

## 6. Accessibility

- Risk level is never conveyed by color alone — always paired with a text label (Critical/High/Medium/Low) and the waveform shape, per §1.
- All interactive elements (row actions, filter controls, publish/export buttons) are keyboard-navigable with visible focus states — a security tool's admin audience skews toward power users who expect keyboard-first workflows.
- Contrast ratios meet WCAG AA at minimum for both the dark (default) and light theme variants.
