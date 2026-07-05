package policy

import (
	"context"
	"testing"
	"time"
)

// TestOPAEngine_EvalStaysSubMillisecond is the regression gate for
// docs/00-統一開發計畫（定案版）.md §四's "OPA評估要壓在毫秒級" requirement:
// a single Evaluate call (already-compiled query, only the eval step) must
// stay comfortably under one millisecond so gating every shell command or
// MCP tool call through OPA is not a perceptible latency regression versus
// the Go-native Engine. This runs a real Decision-producing call (not a
// microbenchmark in isolation) against the shipped default policy, so it
// exercises the same input-marshaling + eval + result-decoding path
// production traffic does.
func TestOPAEngine_EvalStaysSubMillisecond(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive; skipped in -short")
	}
	cfg, err := LoadConfig(defaultPolicyPath(t))
	if err != nil {
		t.Fatalf("loading default policy: %v", err)
	}
	e, err := NewOPA(context.Background(), cfg)
	if err != nil {
		t.Fatalf("constructing OPAEngine: %v", err)
	}
	facts := Facts{Raw: "rm -rf /", Command: "rm", Args: []string{"-rf", "/"}, Target: "/"}

	// Warm up: the first eval pays for one-time JIT/allocator setup inside
	// OPA's topdown evaluator that steady-state calls don't repeat.
	for i := 0; i < 10; i++ {
		e.Evaluate(facts)
	}

	const iterations = 200
	start := time.Now()
	for i := 0; i < iterations; i++ {
		e.Evaluate(facts)
	}
	elapsed := time.Since(start)
	perCall := elapsed / iterations

	const budget = time.Millisecond
	if perCall > budget {
		t.Fatalf("OPAEngine.Evaluate averaged %v/call over %d calls, want < %v", perCall, iterations, budget)
	}
	t.Logf("OPAEngine.Evaluate averaged %v/call over %d calls", perCall, iterations)
}

// BenchmarkOPAEngine_Evaluate is the `go test -bench` counterpart for
// tracking eval cost over time (ns/op, allocs/op) — the sub-millisecond
// test above is the hard gate; this is for watching the trend.
func BenchmarkOPAEngine_Evaluate(b *testing.B) {
	cfg, err := LoadConfig(defaultPolicyPath(b))
	if err != nil {
		b.Fatalf("loading default policy: %v", err)
	}
	e, err := NewOPA(context.Background(), cfg)
	if err != nil {
		b.Fatalf("constructing OPAEngine: %v", err)
	}
	facts := Facts{Raw: "rm -rf /", Command: "rm", Args: []string{"-rf", "/"}, Target: "/"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Evaluate(facts)
	}
}

// BenchmarkEngine_Evaluate is the Go-native baseline, for comparison against
// BenchmarkOPAEngine_Evaluate.
func BenchmarkEngine_Evaluate(b *testing.B) {
	cfg, err := LoadConfig(defaultPolicyPath(b))
	if err != nil {
		b.Fatalf("loading default policy: %v", err)
	}
	e := New(cfg)
	facts := Facts{Raw: "rm -rf /", Command: "rm", Args: []string{"-rf", "/"}, Target: "/"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Evaluate(facts)
	}
}
