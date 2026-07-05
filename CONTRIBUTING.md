# Contributing to Damping

Thank you for considering a contribution. The two most valuable things you can bring us are:

1. **A false positive** — a normal, everyday command that Damping wrongly flagged. This is the single most important kind of bug report for a tool like this (see `docs/threat-model.md` and `docs/00-統一開發計畫（定案版）.md`: false positives are what get a security tool uninstalled).
2. **A bypass** — a way to construct a genuinely dangerous command that Damping's default policy fails to catch.

Both should become a permanent, non-negotiable regression scenario — never a silent one-off fix.

## Before you start

See [`CLAUDE.md`](CLAUDE.md) for the full repository map, build/test commands, the BDD-first development methodology, and the rules for adding or changing a policy rule (every rule needs both a "blocks the dangerous case" scenario and a "doesn't block the safe case" scenario — a rule without both directions of test coverage will not be merged).

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, ...) — this project publishes an automatic changelog from commit history, so message quality matters.

## Code of conduct

Be direct, be kind, assume good faith. Disagreements about whether something is a false positive or a real bypass are exactly the kind of thing worth arguing about carefully — that's the core product discipline, not just a community norm.
