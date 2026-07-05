module github.com/amplify-lab/damping/cli

go 1.26.4

require (
	github.com/amplify-lab/damping/core v0.0.0
	mvdan.cc/sh/v3 v3.13.1
)

require (
	github.com/cucumber/gherkin/go/v26 v26.2.0 // indirect
	github.com/cucumber/godog v0.15.1 // indirect
	github.com/cucumber/messages/go/v21 v21.0.1 // indirect
	github.com/gofrs/uuid v4.3.1+incompatible // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-memdb v1.3.4 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)

// Pre-release monorepo: core has no tagged version yet, so pin it to the
// sibling directory. Standard Go workspace (go.work at the repo root) should
// make this unnecessary for local dev, but this replace keeps `go build`/
// `go test` working unconditionally for any fresh clone or CI runner that
// doesn't pick up go.work. Once core cuts its first tagged release, drop
// this line and require a real version instead.
replace github.com/amplify-lab/damping/core => ../core
