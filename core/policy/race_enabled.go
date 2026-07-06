//go:build race

package policy

// raceModeEnabled is true when this binary was built with `go test -race` (or
// any other `-race` build) — see opa_bench_test.go, the one test in this
// package whose assertion is a wall-clock timing budget, which the race
// detector's own instrumentation overhead can blow regardless of whether
// the underlying code got any slower.
const raceModeEnabled = true
