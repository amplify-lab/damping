# Damping — engineering notes

This file is for anyone (human or AI agent) working *on* this codebase. If you're looking for how to *use* Damping, see [`README.md`](README.md) instead.

## Read first

- [`docs/architecture.md`](docs/architecture.md) — module layout, the `ActionEvent`/`Decision` schema, why `core/` and `cli/` are split.
- [`docs/threat-model.md`](docs/threat-model.md) — what Damping defends against, known bypass classes, fail-open vs. fail-closed.
- [`docs/cli-reference.md`](docs/cli-reference.md) — full command surface, hook contract, policy file schema.

## Building and testing

Requires Go 1.26+.

```
cd core && go build ./... && go test ./... -race -count=1
cd ../cli && go build ./... && go test ./... -race -count=1
```

Both modules build and test independently — `cli/go.mod` pins `core` via a `replace ../core` directive until `core` has a tagged release (a root `go.work` also exists for editor/IDE convenience). Before any commit, `go build ./...`, `go vet ./...`, `gofmt -l .` (no output), `golangci-lint run ./...`, and `gosec ./...` should all be clean, from both `core/` and `cli/`.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the BDD-first development methodology and policy-rule conventions.
