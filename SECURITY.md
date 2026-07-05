# Security Policy

Damping is a security tool. If it has a vulnerability, that's not an embarrassment to hide — it's the single most important kind of bug report we can get, and we'd rather hear about it privately, first.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a security vulnerability. Instead:

- Email **security@damping.dev** (placeholder — confirm final domain per `docs/00-統一開發計畫（定案版）.md` §二 naming checks) with a description of the issue, steps to reproduce, and (if applicable) a proof-of-concept command/policy that demonstrates a bypass.
- If you've found a way to defeat a specific default policy rule (e.g. a new shell-parsing bypass not covered in `docs/threat-model.md` §3), that's exactly the kind of report we want — please include the exact command and which rule you expected to fire.

We aim to acknowledge reports within 72 hours and to ship a fix (plus a permanent regression scenario in `features/`) before any public disclosure.

## Scope

In scope:
- Bypasses of any default policy rule shipped in `cli/policies/default.yaml`
- Ways to disable or tamper with Damping's own enforcement outside the sanctioned `damping off` path (see `docs/threat-model.md` §4)
- Audit log integrity issues (a record that can be silently altered or dropped)
- Anything that causes Damping to report `allow` when the correct verdict was `deny`
- Ways to defeat `damping dashboard`'s Host-header/DNS-rebinding protection while it's bound to its default `127.0.0.1` (see `docs/threat-model.md` §10) — reading the audit log from a webpage that shouldn't be able to is exactly the kind of report we want

Out of scope (for now, until Phase 3+ ships these components):
- MCP Gateway / OAuth 2.1 / confused-deputy issues (not yet implemented — see `docs/architecture.md` §7)
- Team dashboard / enterprise compliance reporting (Phase 4/5, not yet built — not to be confused with the already-shipped local `damping dashboard`, which IS in scope above)
- `damping dashboard` having no authentication at all, or being reachable from another local OS user on a shared machine — both are the accepted, documented threat model for this local single-user tool (`docs/threat-model.md` §10), not vulnerabilities

## Supply chain

Damping ships as a single static Go binary specifically to keep its dependency surface small and auditable. Dependency count is monitored deliberately; Dependabot is enabled; releases are expected to publish via provenance-attested builds rather than long-lived tokens, per the lesson from the 2026 Cline npm-token compromise referenced in `docs/threat-model.md`.
