package update

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDetectMethod_Windows(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(installDirEnv, dir)

	m := DetectMethod(`C:\Users\tim\AppData\Local\damping\damping.exe`, "windows")

	if m.Kind != "windows" {
		t.Fatalf("Kind = %q, want windows", m.Kind)
	}
	if m.Executable != "powershell" {
		t.Fatalf("Executable = %q, want powershell", m.Executable)
	}
	wantArgs := []string{
		"-NoProfile", "-Command",
		"irm https://raw.githubusercontent.com/amplify-lab/damping/main/install.ps1 | iex",
	}
	if !equalArgs(m.Args, wantArgs) {
		t.Fatalf("Args = %v, want %v", m.Args, wantArgs)
	}
	if m.NeedsElevation {
		t.Fatalf("NeedsElevation = true for a writable %s, want false", dir)
	}
}

func TestDetectMethod_Windows_NeedsElevationWhenInstallDirNotWritable(t *testing.T) {
	badDir := nonWritableDir(t)
	t.Setenv(installDirEnv, badDir)

	m := DetectMethod(`C:\damping\damping.exe`, "windows")

	if !m.NeedsElevation {
		t.Fatalf("NeedsElevation = false for an unwritable install dir %s, want true", badDir)
	}
}

func TestDetectMethod_Brew(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(installDirEnv, dir)

	// "/Cellar/" is kept as a harmless legacy/defensive match — this project
	// actually ships a Homebrew Cask (see .goreleaser.yaml's
	// homebrew_casks block), never a formula, so real installs always show
	// "/Caskroom/" (TestDetectMethod_Cask below), not this.
	m := DetectMethod("/opt/homebrew/Cellar/damping/0.5.0/bin/damping", "darwin")

	if m.Kind != "brew" {
		t.Fatalf("Kind = %q, want brew", m.Kind)
	}
	if m.Executable != "brew" {
		t.Fatalf("Executable = %q, want brew", m.Executable)
	}
	if !equalArgs(m.Args, []string{"upgrade", "--cask", "damping"}) {
		t.Fatalf("Args = %v, want [upgrade --cask damping]", m.Args)
	}
	if m.NeedsElevation {
		t.Fatal("NeedsElevation = true for brew, want always false")
	}
}

func TestDetectMethod_Cask(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(installDirEnv, dir)

	// The real-world shape: brew links a cask's binary into a shared bin
	// dir, with the actual install living under .../Caskroom/damping/<ver>/.
	m := DetectMethod("/opt/homebrew/Caskroom/damping/0.5.0/damping", "darwin")

	if m.Kind != "brew" {
		t.Fatalf("Kind = %q, want brew for a /Caskroom/ path", m.Kind)
	}
	if !equalArgs(m.Args, []string{"upgrade", "--cask", "damping"}) {
		t.Fatalf("Args = %v, want [upgrade --cask damping] (the cask invocation, not the deprecated formula one)", m.Args)
	}
}

func TestDetectMethod_Cask_ResolvesSymlinkedExecPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(installDirEnv, dir)

	// Mirrors how brew actually installs a cask binary: a real file under
	// Caskroom, symlinked into a shared bin directory (e.g. /usr/local/bin
	// or /opt/homebrew/bin) that's what os.Executable() actually reports —
	// the raw path never shows "/Caskroom/" at all until resolved.
	caskroomBin := filepath.Join(dir, "Caskroom", "damping", "0.5.0", "damping")
	if err := os.MkdirAll(filepath.Dir(caskroomBin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caskroomBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkedExecPath := filepath.Join(dir, "bin", "damping")
	if err := os.MkdirAll(filepath.Dir(symlinkedExecPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(caskroomBin, symlinkedExecPath); err != nil {
		t.Fatal(err)
	}

	m := DetectMethod(symlinkedExecPath, "darwin")

	if m.Kind != "brew" {
		t.Fatalf("Kind = %q, want brew — DetectMethod must resolve the symlink to see /Caskroom/", m.Kind)
	}
}

func TestDetectMethod_Brew_NeedsElevationAlwaysFalseEvenIfInstallDirUnwritable(t *testing.T) {
	badDir := nonWritableDir(t)
	t.Setenv(installDirEnv, badDir)

	m := DetectMethod("/home/linuxbrew/.linuxbrew/Caskroom/damping/0.5.0/damping", "linux")

	if m.NeedsElevation {
		t.Fatal("brew's NeedsElevation must always be false — brew manages its own permissions")
	}
}

func TestDetectMethod_Script(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(installDirEnv, dir)

	m := DetectMethod("/usr/local/bin/damping", "linux")

	if m.Kind != "script" {
		t.Fatalf("Kind = %q, want script", m.Kind)
	}
	if m.Executable != "sh" {
		t.Fatalf("Executable = %q, want sh", m.Executable)
	}
	wantArgs := []string{
		"-c",
		"curl -fsSL https://raw.githubusercontent.com/amplify-lab/damping/main/install.sh | sh",
	}
	if !equalArgs(m.Args, wantArgs) {
		t.Fatalf("Args = %v, want %v", m.Args, wantArgs)
	}
	if m.NeedsElevation {
		t.Fatalf("NeedsElevation = true for a writable %s, want false", dir)
	}
}

func TestDetectMethod_Script_NeedsElevationWhenInstallDirNotWritable(t *testing.T) {
	badDir := nonWritableDir(t)
	t.Setenv(installDirEnv, badDir)

	m := DetectMethod("/usr/local/bin/damping", "linux")

	if !m.NeedsElevation {
		t.Fatalf("NeedsElevation = false for an unwritable install dir %s, want true", badDir)
	}
}

func TestDetectMethod_Script_DefaultInstallDirWhenEnvUnset(t *testing.T) {
	t.Setenv(installDirEnv, "") // explicitly unset for this test, isolated from the OS env

	m := DetectMethod("/usr/local/bin/damping", "linux")

	// Just confirm this doesn't panic and produces a script method; the
	// real default (/usr/local/bin) is very likely writable only as root,
	// so we don't assert NeedsElevation's value here — only that detection
	// itself is well-formed without DAMPING_INSTALL_DIR set.
	if m.Kind != "script" {
		t.Fatalf("Kind = %q, want script", m.Kind)
	}
}

func TestDetectMethod_Script_InstallDirTracksRunningBinaryLocation(t *testing.T) {
	t.Setenv(installDirEnv, "") // no explicit override — must derive from execPath

	dir := t.TempDir()
	binPath := filepath.Join(dir, "custom-location", "damping")
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	m := DetectMethod(binPath, "linux")

	want := filepath.Dir(binPath)
	if m.InstallDir != want {
		t.Fatalf("InstallDir = %q, want %q (the running binary's actual directory, not a hardcoded default) — a DAMPING_INSTALL_DIR=~/bin custom install must self-update in place, not gain a second stray copy elsewhere", m.InstallDir, want)
	}
	// A writable custom location must not need elevation, proving the probe
	// itself followed InstallDir rather than still checking /usr/local/bin.
	if m.NeedsElevation {
		t.Fatalf("NeedsElevation = true for writable custom dir %s, want false", want)
	}
}

// TestInstallDir_FallsBackToPlatformDefaultWhenExecPathUnknown exercises
// installDir's actual hardcoded-fallback branch directly — only reached
// when there's no resolved execPath at all (CurrentMethod's os.Executable()
// failed) and no DAMPING_INSTALL_DIR override, for both goos values.
func TestInstallDir_FallsBackToPlatformDefaultWhenExecPathUnknown(t *testing.T) {
	t.Setenv(installDirEnv, "")

	if got := installDir("", "linux"); got != "/usr/local/bin" {
		t.Fatalf(`installDir("", "linux") = %q, want "/usr/local/bin"`, got)
	}

	localAppData := filepath.Join(t.TempDir(), "AppData", "Local")
	t.Setenv("LOCALAPPDATA", localAppData)
	want := filepath.Join(localAppData, "damping")
	if got := installDir("", "windows"); got != want {
		t.Fatalf(`installDir("", "windows") = %q, want %q`, got, want)
	}
}

func TestMethod_Display(t *testing.T) {
	cases := []struct {
		name string
		m    Method
		want string
	}{
		{
			name: "script",
			m:    Method{Kind: "script", Executable: "sh", Args: []string{"-c", scriptInstallCmd}},
			want: "curl -fsSL https://raw.githubusercontent.com/amplify-lab/damping/main/install.sh | sh",
		},
		{
			name: "windows",
			m:    Method{Kind: "windows", Executable: "powershell", Args: []string{"-NoProfile", "-Command", windowsInstallCmd}},
			want: "irm https://raw.githubusercontent.com/amplify-lab/damping/main/install.ps1 | iex",
		},
		{
			name: "brew",
			m:    Method{Kind: "brew", Executable: "brew", Args: []string{"upgrade", "--cask", "damping"}},
			want: "brew upgrade --cask damping",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.m.Display()
			if got != tc.want {
				t.Fatalf("Display() = %q, want %q", got, tc.want)
			}
			// Display must always be valid, directly-pasteable shell — never
			// literally containing the argv-wrapping Executable/Args uses
			// internally (e.g. "sh -c ..."), which loses its own quoting
			// when naively joined with spaces.
			if strings.Contains(got, tc.m.Executable+" -c ") || strings.Contains(got, tc.m.Executable+" -Command") {
				t.Fatalf("Display() = %q still shows the argv wrapper, want the real pasteable command", got)
			}
		})
	}
}

func TestCurrentMethod_Smoke(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(installDirEnv, dir)

	m := CurrentMethod()

	switch m.Kind {
	case "script", "brew", "windows":
	default:
		t.Fatalf("CurrentMethod().Kind = %q, want one of script/brew/windows", m.Kind)
	}
	if runtime.GOOS == "windows" && m.Kind != "windows" {
		t.Fatalf("CurrentMethod() on windows returned Kind %q", m.Kind)
	}
}

func TestApply_StreamsOutputAndReturnsCommandError(t *testing.T) {
	var buf bytes.Buffer
	ok := Method{Kind: "script", Executable: "sh", Args: []string{"-c", "echo hello-from-apply"}}

	if err := Apply(context.Background(), ok, &buf); err != nil {
		t.Fatalf("Apply of a succeeding command returned error: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("hello-from-apply")) {
		t.Fatalf("Apply did not stream command output, got %q", buf.String())
	}

	buf.Reset()
	failing := Method{Kind: "script", Executable: "sh", Args: []string{"-c", "echo boom >&2; exit 7"}}
	err := Apply(context.Background(), failing, &buf)
	if err == nil {
		t.Fatal("Apply of a failing command returned nil error, want non-nil")
	}
	if !bytes.Contains(buf.Bytes(), []byte("boom")) {
		t.Fatalf("Apply did not stream stderr output, got %q", buf.String())
	}
}

func TestApply_ExportsInstallDirIntoChildEnv(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	m := Method{Kind: "script", Executable: "sh", Args: []string{"-c", "echo $DAMPING_INSTALL_DIR"}, InstallDir: dir}

	if err := Apply(context.Background(), m, &buf); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != dir {
		t.Fatalf("child saw DAMPING_INSTALL_DIR=%q, want %q — install.sh/install.ps1 rely on this to target the running binary's real location", got, dir)
	}
}

func TestApply_EmptyInstallDirLeavesChildEnvUntouched(t *testing.T) {
	// The "brew" Method never sets InstallDir (brew manages its own paths)
	// — Apply must not export an empty DAMPING_INSTALL_DIR= in that case,
	// which would look like an explicit-but-empty override to a script that
	// checks `${DAMPING_INSTALL_DIR:-default}`.
	var buf bytes.Buffer
	m := Method{Kind: "brew", Executable: "sh", Args: []string{"-c", `[ -z "${DAMPING_INSTALL_DIR+set}" ] && echo unset || echo "set=$DAMPING_INSTALL_DIR"`}}

	if err := Apply(context.Background(), m, &buf); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "unset" {
		t.Fatalf("expected DAMPING_INSTALL_DIR to be left unset in the child env, got %q", got)
	}
}

// TestApply_CancelKillsWholeProcessGroup is the mutation-test target for
// setProcessGroup: a canceled context must take down curl-pipe-sh's
// grandchildren, not just the top-level sh. It proves this by having the
// child spawn a detached-looking grandchild (a second `sh -c 'sleep ...'`,
// analogous to the real curl/installer sh curl-pipe-sh forks) that writes a
// marker file right before it would exit; canceling the context and then
// waiting past the grandchild's sleep must never let that marker appear.
func TestApply_CancelKillsWholeProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group kill is a non-windows-only fix; see method_windows.go")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "grandchild-finished")
	script := "sh -c 'sleep 2; touch " + marker + "' & wait"

	ctx, cancel := context.WithCancel(context.Background())
	m := Method{Kind: "script", Executable: "sh", Args: []string{"-c", script}}

	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- Apply(ctx, m, &buf) }()

	time.Sleep(300 * time.Millisecond) // give the grandchild time to actually start
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Apply did not return promptly after context cancellation")
	}

	time.Sleep(2500 * time.Millisecond) // past the grandchild's own sleep, if it survived
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("grandchild process survived context cancellation and wrote its marker — process group was not killed")
	}
}

func TestDirWritable_NeverCreatesDirectories(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "does", "not", "exist", "yet")

	if !dirWritable(target) {
		t.Fatalf("expected dirWritable(%s) to report writable via its nearest existing ancestor (%s)", target, base)
	}
	if _, err := os.Stat(filepath.Join(base, "does")); !os.IsNotExist(err) {
		t.Fatalf("dirWritable must never create the probed directory (or any ancestor) as a side effect, but %s now exists", filepath.Join(base, "does"))
	}
}

// equalArgs is a tiny slice-equality helper (avoids pulling in
// slices.Equal's import churn just for a handful of test comparisons).
func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// nonWritableDir returns a directory path that dirWritable's ancestor walk
// can never report as writable, regardless of the running user's privileges
// (including root, which is why this doesn't rely on permission bits): the
// nearest existing ancestor it will find is a regular file, not a
// directory, which dirWritable treats as unwritable outright.
func nonWritableDir(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	blocker := filepath.Join(parent, "blocked-by-a-file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing blocker file: %v", err)
	}
	return filepath.Join(blocker, "sub", "damping")
}
