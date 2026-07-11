// Package update implements damping's own update-check and self-update:
// a low-cost "is a newer release out?" probe (cached to at most once per
// day, network-optional, never fatal) plus the machinery to actually apply
// an update on whatever channel the running binary came from (the install
// script, Homebrew, or the Windows installer). See docs/cli-reference.md
// for the user-facing `damping update` command this package backs.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amplify-lab/damping/cli/paths"
	"github.com/amplify-lab/damping/core/atomicfile"
)

// githubAPIBase is the GitHub API origin. It's a package-level var (not a
// const) purely so tests can repoint it at an httptest server instead of
// making real network calls — see check_test.go.
var githubAPIBase = "https://api.github.com"

// releasesPath is the fixed repo this binary checks against. Damping only
// ever has one release stream today (see CLAUDE.md: damping/ is the sole
// public artifact), so there's no per-channel parameterization here.
const releasesPath = "/repos/amplify-lab/damping/releases/latest"

// noUpdateCheckEnv, when set to any non-empty value, disables Check
// entirely — no cache read, no network. Exists for CI, offline
// environments, and anyone who just doesn't want a CLI phoning home on
// every invocation.
const noUpdateCheckEnv = "DAMPING_NO_UPDATE_CHECK"

// cacheFreshness is how long a cached result is trusted before Check will
// hit the network again. 24h keeps the check to "at most once a day" for a
// CLI that may be invoked dozens of times per session (every hook call
// included), without ever going fully silent for long-lived installs.
const cacheFreshness = 24 * time.Hour

// networkTimeout bounds the one GET Check may issue. It's deliberately
// small: this check rides along on every damping invocation, so a slow or
// black-holed network must never make the CLI itself feel slow.
const networkTimeout = 1500 * time.Millisecond

// Info describes the result of an update check.
type Info struct {
	Current   string
	Latest    string
	Available bool
}

// cacheState is the on-disk shape of paths.UpdateCheck() — deliberately
// tiny, just enough to answer "do we already know, recently enough?".
type cacheState struct {
	Latest    string    `json:"latest"`
	CheckedAt time.Time `json:"checked_at"`
}

// githubRelease is the (small) slice of GitHub's release JSON this package
// actually reads. GitHub's real payload has dozens of other fields; we
// decode into this narrow struct so unrelated schema changes upstream
// don't matter to us.
type githubRelease struct {
	TagName string `json:"tag_name"`
}

// Check returns update info for currentVersion. It is designed to be safe
// to call unconditionally on every CLI invocation that only wants to print
// a passive, non-alarming background notice (init/status/doctor/dashboard,
// via Info.Notify):
//
//   - If DAMPING_NO_UPDATE_CHECK is set, it does nothing at all (no cache
//     read, no network) and returns immediately. This governs ONLY these
//     passive background notices — it must never be consulted by an
//     explicit, human-typed `damping update` invocation, which asked a real
//     question and must get a real answer. See ForceCheck for that case.
//   - If the on-disk cache (paths.UpdateCheck()) was written within the
//     last 24h, it's used as-is — zero network calls.
//   - Otherwise, Check performs exactly one GET against the GitHub releases
//     API, bounded by a 1.5s timeout, and rewrites the cache with whatever
//     it learns (even a total failure still records "checked just now" for
//     the empty result already on disk, if any — that way an offline
//     machine pays the timeout at most once a day too, not on every
//     invocation).
//
// Every failure mode (offline, timeout, malformed JSON, unwritable cache,
// unresolvable home directory) is swallowed. Check never returns an error;
// worst case it reports Info{Current: currentVersion} with Available
// false, identical to "no update available."
func Check(ctx context.Context, currentVersion string) Info {
	if os.Getenv(noUpdateCheckEnv) != "" {
		return Info{Current: currentVersion}
	}
	return checkUncached(ctx, currentVersion)
}

// ForceCheck is Check without the DAMPING_NO_UPDATE_CHECK escape hatch: it
// always consults the cache/network, using the exact same freshness window
// and swallow-every-failure contract Check documents, differing only in
// never short-circuiting on that env var. It still USES and refreshes the
// on-disk cache like Check does — this is not a "bypass the cache" knob,
// only a "bypass the opt-out" one.
//
// Exists specifically for `damping update` (cli/cmd/update.go):
// DAMPING_NO_UPDATE_CHECK exists to quiet the passive notice every other
// command prints unconditionally on the way to doing something else, not to
// make an explicit `damping update` invocation lie "already up to date"
// without ever having looked — the user typed that command to ask exactly
// this question.
func ForceCheck(ctx context.Context, currentVersion string) Info {
	return checkUncached(ctx, currentVersion)
}

// checkUncached is the shared cache/network/fallback logic behind both
// Check and ForceCheck, once the DAMPING_NO_UPDATE_CHECK decision (if any)
// has already been made by the caller.
func checkUncached(ctx context.Context, currentVersion string) Info {
	cachePath, pathErr := paths.UpdateCheck()

	var cached cacheState
	haveCache := false
	if pathErr == nil {
		if cs, ok := readCache(cachePath); ok {
			cached = cs
			haveCache = true
			if time.Since(cs.CheckedAt) < cacheFreshness {
				return buildInfo(currentVersion, cs.Latest)
			}
		}
	}
	if !haveCache {
		// The disk cache is missing/unreadable (not merely stale — a stale-
		// but-present disk cache already has its own network-failure
		// fallback below). Before ever hitting the network, fall back to
		// this same process's own last-known-fresh result: see
		// memoryFallback's doc comment for why this matters.
		if cs, ok := memoryFallbackFresh(); ok {
			return buildInfo(currentVersion, cs.Latest)
		}
	}

	latest, fetched := fetchLatest(ctx)
	if !fetched && haveCache {
		// Total failure (offline, timeout, bad JSON, non-200): don't let a
		// transient blip erase a previously-known "yes, an update exists."
		latest = cached.Latest
	}

	fresh := cacheState{Latest: latest, CheckedAt: time.Now()}
	persisted := pathErr == nil && writeCache(cachePath, fresh)
	if !persisted {
		rememberMemoryFallback(fresh)
	}

	return buildInfo(currentVersion, latest)
}

// memoryFallback is the in-process last-resort behind the on-disk cache,
// for the one situation the disk cache can't cover by itself: an unwritable
// ~/.damping (read-only home directory, permissions problem). Without this,
// a long-running process against such an install — cli/dashboard's HTTP
// handlers call Check on every GET /api/version — would hit the network on
// every single call, since there's never a persisted "checked recently" to
// read back. It only ever gets populated when writeCache just failed (see
// checkUncached), so a healthy, writable ~/.damping never touches it at
// all. Mutex-guarded: the dashboard serves requests concurrently.
var memoryFallback struct {
	mu    sync.Mutex
	state cacheState
	valid bool
}

func memoryFallbackFresh() (cacheState, bool) {
	memoryFallback.mu.Lock()
	defer memoryFallback.mu.Unlock()
	if !memoryFallback.valid || time.Since(memoryFallback.state.CheckedAt) >= cacheFreshness {
		return cacheState{}, false
	}
	return memoryFallback.state, true
}

func rememberMemoryFallback(cs cacheState) {
	memoryFallback.mu.Lock()
	defer memoryFallback.mu.Unlock()
	memoryFallback.state = cs
	memoryFallback.valid = true
}

// fetchLatest performs the single network call Check is allowed to make.
// The bool return is whether a usable tag was actually learned — false
// covers every failure mode uniformly (request construction, network,
// non-200, malformed JSON, empty tag), since callers only care about
// "did we learn something" vs. "swallow and move on."
func fetchLatest(ctx context.Context) (string, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, networkTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, githubAPIBase+releasesPath, nil)
	if err != nil {
		return "", false
	}
	// GitHub's API 403s any request with no User-Agent header at all —
	// net/http sets none by default, so this must be explicit.
	req.Header.Set("User-Agent", "damping-cli")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", false
	}
	if rel.TagName == "" {
		return "", false
	}
	return rel.TagName, true
}

// readCache loads the cached check result, if any. Any failure (missing
// file, unreadable, malformed JSON) reports ok=false — a cache is purely
// an optimization, never a source of truth Check must trust.
func readCache(path string) (cacheState, bool) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is paths.UpdateCheck()'s fixed ~/.damping/update-check.json path (or $DAMPING_HOME override), not an attacker-influenced path
	if err != nil {
		return cacheState{}, false
	}
	var cs cacheState
	if err := json.Unmarshal(data, &cs); err != nil {
		return cacheState{}, false
	}
	return cs, true
}

// writeCache persists the check result, reporting whether it actually
// succeeded. A false return is swallowed by every caller per Check's
// contract (a caching problem must never surface as a caller-visible
// error) — checkUncached uses it only to decide whether memoryFallback
// needs to stand in for a disk cache this process couldn't write (unwritable
// home directory, read-only filesystem, ...). Uses atomicfile so a crash or
// disk-full mid-write can never corrupt or truncate a previously-good cache
// file (matching this repo's convention for every other in-place config
// write — see core/atomicfile's doc comment).
func writeCache(path string, cs cacheState) bool {
	data, err := json.Marshal(cs)
	if err != nil {
		return false
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false
	}
	return atomicfile.Write(path, data, 0o600) == nil
}

// buildInfo assembles Info from the two raw version strings. Available is
// only set when both parse as plain "vMAJOR.MINOR.PATCH" and latest is
// strictly greater — see parseVersion's doc comment for why "dev" (and
// anything else non-conforming) always yields Available=false rather than
// a guess.
func buildInfo(current, latest string) Info {
	info := Info{Current: current, Latest: latest}
	if latest == "" {
		return info
	}
	cur, curOK := parseVersion(current)
	lat, latOK := parseVersion(latest)
	info.Available = curOK && latOK && versionLess(cur, lat)
	return info
}

// parseVersion parses a plain "vMAJOR.MINOR.PATCH" tag (e.g. "v0.5.0") into
// its three integer components. This project's real tags are all this
// simple shape (v0.5.0, v0.4.1, v0.2.1 — see git tags), so a manual
// strip-"v"-and-split is sufficient and avoids pulling in a semver library
// for one comparison. Anything else — "dev" (root.go's documented default
// for a non-release build), a pre-release suffix, a malformed tag — is
// deliberately treated as "can't compare" (ok=false) rather than guessed
// at; buildInfo relies on that to never claim an update is available when
// it isn't sure.
func parseVersion(v string) ([3]int, bool) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// versionLess reports whether a < b under ordinary major.minor.patch
// ordering.
func versionLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// Notify writes a single, non-alarming line to w when an update is
// available, and writes nothing otherwise — safe to call unconditionally
// after Check on every invocation without it ever being noisy for the
// common case (already up to date).
func (i Info) Notify(w io.Writer) {
	if !i.Available {
		return
	}
	fmt.Fprintf(w, "ℹ damping %s is available (you have %s) — run 'damping update'\n", i.Latest, i.Current)
}
