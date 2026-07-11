package update

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amplify-lab/damping/cli/paths"
)

// withGithubAPIBase points githubAPIBase at a fake server for the duration
// of the test and restores the real value afterward, so tests never leak
// state into each other (or, worse, into a real network call from a later
// test that forgot to set it up).
func withGithubAPIBase(t *testing.T, url string) {
	t.Helper()
	prev := githubAPIBase
	githubAPIBase = url
	t.Cleanup(func() { githubAPIBase = prev })
}

// setDampingHome points DAMPING_HOME at a fresh throwaway directory and
// returns it, following this repo's convention (see e.g.
// adapter/mcp/wrap_test.go's use of t.Setenv("DAMPING_HOME", ...)) for
// isolating each test's on-disk state. Also resets the package-level
// memoryFallback guard (see checkUncached) — it's process-global, not
// per-DAMPING_HOME, so without this reset a test running earlier in this
// same binary that happened to trigger it (an unwritable-cache scenario)
// could silently make a later, unrelated test skip a network call it
// expects to make.
func setDampingHome(t *testing.T) string {
	t.Helper()
	resetMemoryFallback(t)
	dir := filepath.Join(t.TempDir(), "damping-home")
	t.Setenv("DAMPING_HOME", dir)
	return dir
}

// resetMemoryFallback clears memoryFallback's state before and after a
// test, so tests that deliberately exercise it (an unwritable cache) can't
// leak that state into whichever test happens to run next in this binary.
func resetMemoryFallback(t *testing.T) {
	t.Helper()
	clear := func() {
		memoryFallback.mu.Lock()
		memoryFallback.state = cacheState{}
		memoryFallback.valid = false
		memoryFallback.mu.Unlock()
	}
	clear()
	t.Cleanup(clear)
}

func writeCacheFile(t *testing.T, cs cacheState) {
	t.Helper()
	path, err := paths.UpdateCheck()
	if err != nil {
		t.Fatalf("paths.UpdateCheck: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	data, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}
}

func readCacheFile(t *testing.T) (cacheState, bool) {
	t.Helper()
	path, err := paths.UpdateCheck()
	if err != nil {
		t.Fatalf("paths.UpdateCheck: %v", err)
	}
	cs, ok := readCache(path)
	return cs, ok
}

// fatalServer is an httptest server that fails the test immediately if it
// ever receives a request — used to prove "this code path makes zero
// network calls" instead of merely hoping so.
func fatalServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unexpected network call: this scenario must make zero HTTP calls")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheck_FreshCacheMakesNoNetworkCall(t *testing.T) {
	setDampingHome(t)
	withGithubAPIBase(t, fatalServer(t).URL)

	writeCacheFile(t, cacheState{Latest: "v9.9.9", CheckedAt: time.Now().Add(-1 * time.Hour)})

	info := Check(context.Background(), "v1.0.0")

	if info.Current != "v1.0.0" || info.Latest != "v9.9.9" {
		t.Fatalf("Check returned %+v, want Current v1.0.0 / Latest v9.9.9 straight from the fresh cache", info)
	}
	if !info.Available {
		t.Fatalf("Check returned %+v, want Available true (v9.9.9 > v1.0.0)", info)
	}
}

func TestCheck_StaleCacheFetchesAndRewritesCache(t *testing.T) {
	setDampingHome(t)

	var gotUserAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		if r.URL.Path != releasesPath {
			t.Errorf("unexpected request path %q, want %q", r.URL.Path, releasesPath)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v2.0.0"}`))
	}))
	t.Cleanup(srv.Close)
	withGithubAPIBase(t, srv.URL)

	// No pre-existing cache at all — the "missing" half of "stale/missing".
	info := Check(context.Background(), "v1.0.0")

	if info != (Info{Current: "v1.0.0", Latest: "v2.0.0", Available: true}) {
		t.Fatalf("Check returned %+v, want {v1.0.0 v2.0.0 true}", info)
	}
	if gotUserAgent == "" {
		t.Fatal("outgoing request had no User-Agent header — GitHub's API 403s these")
	}

	cs, ok := readCacheFile(t)
	if !ok {
		t.Fatal("expected Check to have written a cache file, found none/unreadable")
	}
	if cs.Latest != "v2.0.0" {
		t.Fatalf("cached Latest = %q, want v2.0.0", cs.Latest)
	}
	if time.Since(cs.CheckedAt) > time.Minute {
		t.Fatalf("cached CheckedAt = %v, want ~now", cs.CheckedAt)
	}

	// And now that the cache is fresh, a second call must not hit the
	// network again — reuse fatalServer to prove it.
	withGithubAPIBase(t, fatalServer(t).URL)
	info2 := Check(context.Background(), "v1.0.0")
	if info2.Latest != "v2.0.0" {
		t.Fatalf("second Check (should read the now-fresh cache) returned %+v", info2)
	}
}

func TestCheck_StaleExistingCacheAlsoRefetches(t *testing.T) {
	setDampingHome(t)
	writeCacheFile(t, cacheState{Latest: "v1.5.0", CheckedAt: time.Now().Add(-25 * time.Hour)})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v2.0.0"}`))
	}))
	t.Cleanup(srv.Close)
	withGithubAPIBase(t, srv.URL)

	info := Check(context.Background(), "v1.0.0")
	if info.Latest != "v2.0.0" {
		t.Fatalf("Check with a >24h-old cache returned Latest %q, want v2.0.0 (should have refetched)", info.Latest)
	}
}

func TestCheck_NoUpdateCheckEnvSkipsEverything(t *testing.T) {
	setDampingHome(t)
	t.Setenv(noUpdateCheckEnv, "1")
	withGithubAPIBase(t, fatalServer(t).URL)

	// Seed a cache file and confirm Check doesn't even read it (let alone
	// the network): the returned Info must be exactly the zero-info form,
	// not whatever the seeded cache said.
	writeCacheFile(t, cacheState{Latest: "v9.9.9", CheckedAt: time.Now()})

	info := Check(context.Background(), "v1.0.0")

	want := Info{Current: "v1.0.0"}
	if info != want {
		t.Fatalf("Check with %s set returned %+v, want %+v", noUpdateCheckEnv, info, want)
	}
}

// TestForceCheck_IgnoresNoUpdateCheckEnv is the core regression test for the
// Check/ForceCheck split: `damping update` (via ForceCheck) must still
// answer for real even with DAMPING_NO_UPDATE_CHECK set — see
// TestCheck_StillObeysNoUpdateCheckEnv immediately below for the other half.
func TestForceCheck_IgnoresNoUpdateCheckEnv(t *testing.T) {
	setDampingHome(t)
	t.Setenv(noUpdateCheckEnv, "1")
	writeCacheFile(t, cacheState{Latest: "v9.9.9", CheckedAt: time.Now()})

	info := ForceCheck(context.Background(), "v1.0.0")

	if info.Latest != "v9.9.9" || !info.Available {
		t.Fatalf("expected ForceCheck to ignore %s and read the fresh cache, got %+v", noUpdateCheckEnv, info)
	}
}

// TestCheck_StillObeysNoUpdateCheckEnv is the other half of the split: the
// plain Check (unlike ForceCheck) must still honor the env var — this is
// what the passive background notices (init/status/doctor/dashboard) rely
// on to actually go quiet under it.
func TestCheck_StillObeysNoUpdateCheckEnv(t *testing.T) {
	setDampingHome(t)
	t.Setenv(noUpdateCheckEnv, "1")
	writeCacheFile(t, cacheState{Latest: "v9.9.9", CheckedAt: time.Now()})

	info := Check(context.Background(), "v1.0.0")

	if info != (Info{Current: "v1.0.0"}) {
		t.Fatalf("expected Check to still honor %s and skip the cache entirely, got %+v", noUpdateCheckEnv, info)
	}
}

// TestCheck_EmptyNoUpdateCheckEnvTreatedAsUnset guards the low-severity edge
// case tests rely on: setting the env var to an explicit empty string (as
// opposed to it simply being absent) must NOT suppress the check — this is
// what lets a test suite that inherits an ambient DAMPING_NO_UPDATE_CHECK=1
// default (see cli/cmd/cmd_test.go's setupTestEnv) still opt back into a
// real check with a plain t.Setenv(..., "").
func TestCheck_EmptyNoUpdateCheckEnvTreatedAsUnset(t *testing.T) {
	setDampingHome(t)
	t.Setenv(noUpdateCheckEnv, "") // explicitly set to empty, not merely absent
	writeCacheFile(t, cacheState{Latest: "v9.9.9", CheckedAt: time.Now()})

	info := Check(context.Background(), "v1.0.0")

	if info.Latest != "v9.9.9" {
		t.Fatalf("expected an empty-string %s to be treated as unset (still check), got %+v", noUpdateCheckEnv, info)
	}
}

func TestCheck_DevCurrentVersionNeverAvailable(t *testing.T) {
	setDampingHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v0.6.0"}`))
	}))
	t.Cleanup(srv.Close)
	withGithubAPIBase(t, srv.URL)

	info := Check(context.Background(), "dev")

	if info.Available {
		t.Fatalf(`Check("dev") returned Available=true (%+v) — "dev" must never be reported as upgradable, only "no comparison possible"`, info)
	}
	if info.Latest != "v0.6.0" {
		t.Fatalf("Check(\"dev\") Latest = %q, want v0.6.0 (still learned, just not comparable)", info.Latest)
	}
}

func TestCheck_NetworkFailureSwallowedAndDoesNotRegressCache(t *testing.T) {
	setDampingHome(t)
	// A previously-known update, cached long enough ago to be stale.
	writeCacheFile(t, cacheState{Latest: "v3.0.0", CheckedAt: time.Now().Add(-25 * time.Hour)})

	// Point at a server that immediately closes the connection / 500s, to
	// exercise the "fetch failed entirely" path without relying on a real
	// timeout (keeps the test fast).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	withGithubAPIBase(t, srv.URL)

	info := Check(context.Background(), "v1.0.0")
	if info.Latest != "v3.0.0" {
		t.Fatalf("Check on total fetch failure returned Latest %q, want the previously-cached v3.0.0 preserved", info.Latest)
	}

	cs, ok := readCacheFile(t)
	if !ok {
		t.Fatal("expected cache to still exist after a failed fetch")
	}
	if time.Since(cs.CheckedAt) > time.Minute {
		t.Fatalf("expected CheckedAt to be refreshed to ~now even on failure (so we don't retry every invocation), got %v", cs.CheckedAt)
	}
}

// TestCheck_FirstRunOffline_NoCacheAndUnreachableServer covers a fresh
// install's very first invocation on a machine with no network: no cache
// file has ever been written, and the "GitHub" endpoint is entirely
// unreachable. Uses an already-closed httptest server (immediate connection
// refusal) rather than a real unroutable IP, so this test stays fast and
// deterministic instead of actually waiting out Check's 1.5s network
// timeout or depending on the test sandbox's own network routing — the
// code path exercised (fetchLatest's request failing outright) is
// identical either way.
func TestCheck_FirstRunOffline_NoCacheAndUnreachableServer(t *testing.T) {
	setDampingHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // closed before any request is made
	withGithubAPIBase(t, srv.URL)

	start := time.Now()
	info := Check(context.Background(), "v1.0.0")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Check took %v against an unreachable server, want well under the 1.5s network timeout", elapsed)
	}
	if info.Available {
		t.Fatalf("expected Available=false on a first run with no cache and an unreachable server, got %+v", info)
	}
	if info.Current != "v1.0.0" {
		t.Fatalf("expected Current still echoed back even on total failure, got %+v", info)
	}

	// Cache handling stays sane afterward: the failed attempt still wrote a
	// well-formed (if empty) cache entry rather than a corrupt file or
	// crashing — this is what makes an offline machine pay the network
	// timeout at most once a day (per Check's own doc comment), not on
	// every single invocation.
	cs, ok := readCacheFile(t)
	if !ok {
		t.Fatal("expected a well-formed cache file to exist after the failed check")
	}
	if cs.Latest != "" {
		t.Fatalf("expected an empty Latest recorded (nothing was ever learned), got %q", cs.Latest)
	}
	if time.Since(cs.CheckedAt) > time.Minute {
		t.Fatalf("expected CheckedAt to be ~now, got %v", cs.CheckedAt)
	}
}

// TestCheck_UnwritableCacheStillThrottlesRepeatCallsInProcess is the
// regression test for memoryFallback: without it, an unwritable ~/.damping
// (read-only home directory) means the on-disk cache can never persist a
// "checked recently" — every single Check call in a long-running process
// (cli/dashboard's HTTP handlers call Check on every GET /api/version)
// would hit the network. Points DAMPING_HOME at a path blocked by a regular
// file (MkdirAll can never succeed against it, regardless of privileges,
// including root) so writeCache is guaranteed to fail both times.
func TestCheck_UnwritableCacheStillThrottlesRepeatCallsInProcess(t *testing.T) {
	setDampingHome(t) // also resets memoryFallback
	blockerParent := t.TempDir()
	blocker := filepath.Join(blockerParent, "blocked-by-a-file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DAMPING_HOME", filepath.Join(blocker, "sub", "damping-home"))

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"tag_name":"v2.0.0"}`))
	}))
	t.Cleanup(srv.Close)
	withGithubAPIBase(t, srv.URL)

	first := Check(context.Background(), "v1.0.0")
	second := Check(context.Background(), "v1.0.0")

	if first.Latest != "v2.0.0" || second.Latest != "v2.0.0" {
		t.Fatalf("expected both calls to report v2.0.0 learned from the one real fetch, got %+v / %+v", first, second)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected exactly 1 network call across two Check calls against an unwritable cache, got %d", got)
	}
}

func TestCheck_MalformedCacheTreatedAsMissing(t *testing.T) {
	dir := setDampingHome(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path, err := paths.UpdateCheck()
	if err != nil {
		t.Fatalf("paths.UpdateCheck: %v", err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write malformed cache: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v2.0.0"}`))
	}))
	t.Cleanup(srv.Close)
	withGithubAPIBase(t, srv.URL)

	info := Check(context.Background(), "v1.0.0")
	if info.Latest != "v2.0.0" {
		t.Fatalf("Check with a malformed cache file returned %+v, want it to treat the cache as missing and refetch", info)
	}
}

func TestInfo_Notify(t *testing.T) {
	cases := []struct {
		name string
		info Info
		want string
	}{
		{
			name: "available",
			info: Info{Current: "v0.5.0", Latest: "v0.6.0", Available: true},
			want: "ℹ damping v0.6.0 is available (you have v0.5.0) — run 'damping update'\n",
		},
		{
			name: "not available",
			info: Info{Current: "v0.5.0", Latest: "v0.5.0", Available: false},
			want: "",
		},
		{
			name: "zero value",
			info: Info{},
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.info.Notify(&buf)
			if buf.String() != tc.want {
				t.Fatalf("Notify wrote %q, want %q", buf.String(), tc.want)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want [3]int
		ok   bool
	}{
		{"v0.5.0", [3]int{0, 5, 0}, true},
		{"v0.4.1", [3]int{0, 4, 1}, true},
		{"0.4.1", [3]int{0, 4, 1}, true},
		{"v0.10.0", [3]int{0, 10, 0}, true}, // multi-digit component — must parse as 10, not two digits
		{"v1.10.23", [3]int{1, 10, 23}, true},
		{"dev", [3]int{}, false},
		{"v1.2", [3]int{}, false},     // short: too few components
		{"v1.2.3.4", [3]int{}, false}, // long: too many components
		{"v1.2.x", [3]int{}, false},
		{"v1.2.3-rc1", [3]int{}, false}, // pre-release suffix rejected, not guessed at
		{"v1.2.3+build5", [3]int{}, false},
		{"", [3]int{}, false},
	}
	for _, tc := range cases {
		got, ok := parseVersion(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("parseVersion(%q) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestVersionLess is a direct test of the ordering comparison itself
// (buildInfo's other tests, e.g. TestCheck_StaleCacheFetchesAndRewritesCache,
// only exercise it indirectly through single-digit fixture versions) —
// the case this project's real early tags (v0.2.x-v0.9.x) never had to
// distinguish from string comparison: "v0.9.9" < "v0.10.0" numerically but
// sorts the other way as plain text, and getting this wrong would make
// `damping update` stop reporting an available update to anyone still on
// e.g. v0.9.x once a v0.10.0+ release ships.
func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.9.9", "v0.10.0", true}, // multi-digit minor: "10" < "9" as strings, but 10 > 9 numerically
		{"v0.10.0", "v0.9.9", false},
		{"v1.2.3", "v1.10.0", true}, // multi-digit minor again, major held equal
		{"v1.10.0", "v1.2.3", false},
		{"v1.2.3", "v1.2.3", false}, // equal versions: neither is less than the other
		{"v0.5.0", "v0.5.1", true},  // patch-only difference
		{"v1.0.0", "v2.0.0", true},  // major-only difference
		{"v2.0.0", "v1.9.9", false}, // major dominates minor/patch regardless of their own ordering
	}
	for _, tc := range cases {
		a, aOK := parseVersion(tc.a)
		b, bOK := parseVersion(tc.b)
		if !aOK || !bOK {
			t.Fatalf("parseVersion unexpectedly failed for %q/%q", tc.a, tc.b)
		}
		if got := versionLess(a, b); got != tc.want {
			t.Errorf("versionLess(%v, %v) [from %q, %q] = %v, want %v", a, b, tc.a, tc.b, got, tc.want)
		}
	}
}

// TestBuildInfo_MultiDigitVersionsEndToEnd proves the same multi-digit
// ordering holds through buildInfo (what Check actually calls), not just
// versionLess in isolation.
func TestBuildInfo_MultiDigitVersionsEndToEnd(t *testing.T) {
	info := buildInfo("v0.9.9", "v0.10.0")
	if !info.Available {
		t.Fatalf("buildInfo(v0.9.9, v0.10.0) = %+v, want Available=true", info)
	}
	info = buildInfo("v0.10.0", "v0.9.9")
	if info.Available {
		t.Fatalf("buildInfo(v0.10.0, v0.9.9) = %+v, want Available=false (already newer)", info)
	}
}
