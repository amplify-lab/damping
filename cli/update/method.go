package update

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// installDirEnv lets a user (or an install script) tell DetectMethod exactly
// where damping was installed, overriding the per-platform default. Mainly
// exists so tests can point the writability probe at a throwaway directory
// instead of the real system install location.
const installDirEnv = "DAMPING_INSTALL_DIR"

// scriptInstallCmd and windowsInstallCmd are the real, directly-pasteable
// one-liners this project's install.sh/install.ps1 docs advertise (see
// README.md's Quick Start). Both DetectMethod's Args (which exec.Command
// needs as separate argv entries, e.g. ["-c", scriptInstallCmd]) and
// Method.Display (which a human copies verbatim into their own shell) are
// built from these same constants, so there is exactly one place that knows
// the actual command text.
const (
	scriptInstallCmd  = "curl -fsSL https://raw.githubusercontent.com/amplify-lab/damping/main/install.sh | sh"
	windowsInstallCmd = "irm https://raw.githubusercontent.com/amplify-lab/damping/main/install.ps1 | iex"
)

// Method describes how to self-update the currently running install.
type Method struct {
	Kind           string // "script" | "brew" | "windows"
	Executable     string
	Args           []string
	NeedsElevation bool
	// InstallDir is the directory Apply should point install.sh/install.ps1
	// at via DAMPING_INSTALL_DIR (see Apply) — empty for "brew", which
	// manages its own Cellar/Caskroom paths and needs no such override.
	InstallDir string
}

// Display renders m as the exact, single-line command a human would type
// themselves — used everywhere `damping update`/the dashboard show a command
// to a person (cli/cmd/update.go). This is deliberately NOT
// strings.Join(append([]string{m.Executable}, m.Args...), " "): for
// "script" and "windows", Executable/Args wrap the real command inside
// `sh -c "..."` / `powershell -Command "..."` for exec.Command's argv-based
// invocation, and naively space-joining those loses the inner quoting —
// e.g. `sh -c curl -fsSL ... | sh` is not valid shell, the pipe runs
// outside the `-c` argument entirely. brew has no such wrapping, so its
// Display is the same join Executable/Args already produce.
func (m Method) Display() string {
	switch m.Kind {
	case "windows":
		return windowsInstallCmd
	case "brew":
		return strings.Join(append([]string{m.Executable}, m.Args...), " ")
	default: // "script"
		return scriptInstallCmd
	}
}

// DetectMethod inspects execPath (normally the result of os.Executable())
// and goos (normally runtime.GOOS) to decide how this install should be
// updated. Both are passed explicitly, rather than read internally, so
// tests can fake "what platform / what install" without needing to control
// the real OS or move the test binary around.
//
// The three channels mirror how damping is actually distributed today (see
// install.sh / install.ps1 and .goreleaser.yaml's homebrew_casks block): a
// curl-pipe-sh/irm installer script is the default on every platform,
// Homebrew is detected via the Cask layout brew actually uses for damping
// ("/Caskroom/" — this project ships a cask, never a formula, so
// "/Cellar/" is kept only as a harmless legacy/defensive check), and
// Windows always goes through the PowerShell installer since there's no
// package manager convention to detect there.
func DetectMethod(execPath, goos string) Method {
	resolved := resolveExecPath(execPath)

	if goos == "windows" {
		dir := installDir(resolved, goos)
		return Method{
			Kind:           "windows",
			Executable:     "powershell",
			Args:           []string{"-NoProfile", "-Command", windowsInstallCmd},
			NeedsElevation: !dirWritable(dir),
			InstallDir:     dir,
		}
	}

	// Cask binaries are typically symlinked into /usr/local/bin or
	// /opt/homebrew/bin (brew links the shim there; the real binary lives
	// under .../Caskroom/damping/<version>/) — the raw execPath as
	// os.Executable() reports it won't contain "/Caskroom/" at all until
	// resolved through that symlink, which is exactly what resolveExecPath
	// does above.
	if strings.Contains(resolved, "/Cellar/") || strings.Contains(resolved, "/Caskroom/") {
		return Method{
			Kind:       "brew",
			Executable: "brew",
			Args:       []string{"upgrade", "--cask", "damping"},
			// brew always runs as the invoking user and manages its own
			// Cellar/Caskroom permissions — there's no elevation story here.
			NeedsElevation: false,
		}
	}

	dir := installDir(resolved, goos)
	return Method{
		Kind:           "script",
		Executable:     "sh",
		Args:           []string{"-c", scriptInstallCmd},
		NeedsElevation: !dirWritable(dir),
		InstallDir:     dir,
	}
}

// CurrentMethod is the production entry point: DetectMethod against the
// real running binary and OS. cli/cmd and cli/dashboard both call this one;
// tests call DetectMethod directly with fake inputs.
func CurrentMethod() Method {
	execPath, err := os.Executable()
	if err != nil {
		// os.Executable() failing is rare (exotic platform/sandbox) but not
		// fatal to detection — an empty execPath just can't match the brew
		// "/Cellar/"/"/Caskroom/" heuristic or resolve to a real install
		// directory, so DetectMethod falls through to "script" targeting the
		// platform default, the safe choice.
		execPath = ""
	}
	return DetectMethod(execPath, runtime.GOOS)
}

// resolveExecPath resolves execPath through any symlink (see DetectMethod's
// Cask comment for why this matters) and returns the result, or execPath
// itself unchanged if it's empty or EvalSymlinks fails — a synthetic path
// in a unit test, or a real path that no longer exists, both just mean
// "match/derive against execPath as given" rather than a hard error.
func resolveExecPath(execPath string) string {
	if execPath == "" {
		return execPath
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		return resolved
	}
	return execPath
}

// installDir resolves the target directory a self-update should write into
// — both for the writability probe and (via Method.InstallDir) for Apply to
// export as DAMPING_INSTALL_DIR into install.sh/install.ps1's environment.
//
// DAMPING_INSTALL_DIR always wins when set — an explicit operator/install-
// script override. Otherwise, the target is derived from where the RUNNING
// binary actually lives (filepath.Dir of the resolved execPath): a
// DAMPING_INSTALL_DIR=~/bin custom install must update itself in ~/bin, not
// silently gain a second stray copy at a hardcoded conventional path. Only
// when resolvedExecPath is empty (CurrentMethod's os.Executable() failed, or
// a test passes "" deliberately) does this fall back to the platform's
// conventional install location.
func installDir(resolvedExecPath, goos string) string {
	if v := os.Getenv(installDirEnv); v != "" {
		return v
	}
	if resolvedExecPath != "" {
		return filepath.Dir(resolvedExecPath)
	}
	if goos == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "damping")
	}
	return "/usr/local/bin"
}

// dirWritable probes whether dir — or, if dir doesn't exist yet, its
// nearest existing ancestor — is writable by the current user, by actually
// creating and removing a temp file there: the only reliable way to answer
// this (permission bits alone can lie: ACLs, read-only mounts, containers).
// Deliberately side-effect-free: this must never create or leave behind any
// directory as a side effect of merely being asked "is this writable" — a
// read-only GET /api/version from the dashboard hits this on every request.
func dirWritable(dir string) bool {
	probeDir := dir
	for {
		info, err := os.Stat(probeDir)
		if err == nil {
			if !info.IsDir() {
				return false // dir, or an ancestor path component, exists but isn't a directory
			}
			break
		}
		if !os.IsNotExist(err) {
			return false // permission denied, I/O error, etc. while walking up — treat as not writable
		}
		parent := filepath.Dir(probeDir)
		if parent == probeDir {
			return false // reached the filesystem root without finding an existing ancestor
		}
		probeDir = parent
	}

	f, err := os.CreateTemp(probeDir, ".damping-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// Apply runs m's command with combined stdout+stderr streamed live to w, so
// the user watching `damping update` sees the real installer's output as it
// happens rather than a silent pause. Returns the command's error verbatim
// (wrapped with a little context).
//
// Apply does NOT check m.NeedsElevation itself — callers must check that
// first (and prompt/re-exec/abort accordingly) before ever calling Apply;
// running an installer that needs elevation without it will simply fail
// with whatever permission error the shell/installer produces.
func Apply(ctx context.Context, m Method, w io.Writer) error {
	cmd := exec.CommandContext(ctx, m.Executable, m.Args...) // #nosec G204 -- m.Executable/m.Args come from DetectMethod's fixed table of self-update commands (script/brew/windows), never attacker- or user-influenced input
	cmd.Stdout = w
	cmd.Stderr = w
	if m.InstallDir != "" {
		// install.sh / install.ps1 both honor DAMPING_INSTALL_DIR as an
		// override for their own hardcoded default — this is what makes the
		// child installer actually target the running binary's real
		// location (or the operator's own explicit override; installDir
		// already folds that in, so m.InstallDir reflects it either way)
		// instead of silently installing a second copy elsewhere.
		cmd.Env = append(os.Environ(), installDirEnv+"="+m.InstallDir)
	}
	// A canceled context must take down the whole command tree, not just
	// the immediate child: m.Executable for the "script" kind is
	// `sh -c "curl ... | sh"`, and sh forks curl plus a second sh to run the
	// piped installer — killing only the top-level sh process leaves those
	// grandchildren running, reparented. setProcessGroup (platform-specific;
	// a no-op on windows, see method_windows.go) makes cancellation kill the
	// whole group.
	setProcessGroup(cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running %s update command: %w", m.Kind, err)
	}
	return nil
}
