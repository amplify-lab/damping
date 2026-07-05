// Package policies embeds the default policy shipped with the damping
// binary. default.yaml here is the single canonical copy — also documented
// in full in docs/cli-reference.md §13 — and core/policy's own tests load
// this exact file by relative path so the shipped default and the tested
// default never drift apart.
package policies

import _ "embed"

//go:embed default.yaml
var Default string
