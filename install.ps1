<#
.SYNOPSIS
    Damping install script for Windows — see README.md's Quick Start, which
    advertises a one-line install for Windows the same way install.sh's
    header advertises `curl -sSL https://damping.dev/install | sh` for
    macOS/Linux. Downloads the pre-built binary matching windows/amd64 from
    a GitHub Release (built by .goreleaser.yaml at the repo root) and
    installs it onto the current user's PATH.

    This is install.sh's exact behavioral mirror for Windows: same steps
    (detect platform, resolve version, download archive + checksums.txt,
    verify SHA-256, extract, install, update PATH), same override env
    vars — just expressed in PowerShell, since Windows has no /bin/sh for
    users to pipe a POSIX script into. Works under both Windows PowerShell
    5.1 (ships with every Windows 10/11 install) and PowerShell 7+ (pwsh).

    Override with environment variables:
      $env:DAMPING_VERSION       install a specific tag instead of latest, e.g. "v1.2.3"
      $env:DAMPING_INSTALL_DIR   install somewhere other than the default, e.g. "C:\tools\damping"
#>

$ErrorActionPreference = 'Stop'
# PS 5.1's default progress-bar rendering (a UI update per buffer chunk)
# drastically slows large Invoke-WebRequest downloads; irm/iwr have no
# separate flag for this, only the global preference.
$ProgressPreference = 'SilentlyContinue'

$Repo = "amplify-lab/damping"
$InstallDir = if ($env:DAMPING_INSTALL_DIR) { $env:DAMPING_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "damping" }
$Version = $env:DAMPING_VERSION

# A previous run may have left "damping.exe.old" behind if the update-in-
# place rename (see Main's Move-Item dance below) ran while the process that
# would eventually delete it never got the chance to — best-effort cleanup
# so stale .old files don't accumulate across repeated installs/updates.
$staleOldBinaryPath = Join-Path $InstallDir "damping.exe.old"
if (Test-Path $staleOldBinaryPath) {
    Remove-Item -Path $staleOldBinaryPath -Force -ErrorAction SilentlyContinue
}

# Windows has no real equivalent of /usr/local/bin that's writable without
# admin rights, so unlike install.sh (which falls back to `sudo mv` when
# /usr/local/bin isn't writable), this script deliberately never asks for
# elevation — %LOCALAPPDATA% is always writable by the current user and is
# the conventional home for a per-user CLI install like this one on Windows.

function Write-Info {
    param([string]$Message)
    Write-Host $Message
}

# Test-SupportedArch mirrors install.sh's detect_os/detect_arch, but for a
# single fixed target: .goreleaser.yaml only ever builds windows/amd64 (it
# explicitly ignores windows/arm64 — cli/ui's TTY prompter has no tested
# Windows/arm64 path yet), so there is nothing to "detect" beyond confirming
# the machine is that one supported target.
function Test-SupportedArch {
    $osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    if ($osArch -ne [System.Runtime.InteropServices.Architecture]::X64) {
        throw "unsupported architecture: $osArch — damping only ships a windows/amd64 binary. See https://github.com/$Repo/releases for manual download options."
    }
}

# Resolve-DampingVersion prints the exact tag to install (e.g. "v1.2.3"),
# either from $env:DAMPING_VERSION or by asking the GitHub API for the
# latest release — the same approach install.sh's resolve_version takes,
# and for the same reason: .goreleaser.yaml's archive names embed the
# version, so letting users pin an exact one is worth the extra request.
# GitHub's REST API rejects requests with no User-Agent header, hence the
# explicit -Headers on every call in this script.
function Resolve-DampingVersion {
    if ($Version) {
        return $Version
    }
    $headers = @{ "User-Agent" = "damping-installer" }
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
    } catch {
        throw "could not resolve the latest release version from the GitHub API: $($_.Exception.Message)"
    }
    if (-not $release.tag_name) {
        throw "could not resolve the latest release version from the GitHub API"
    }
    return $release.tag_name
}

# Test-Checksum confirms $ArchivePath really is the exact file
# .goreleaser.yaml's checksum step recorded for $ArchiveName in the same
# release, throwing (rather than installing an unverified binary) on any
# mismatch or missing entry. This is a straight port of install.sh's
# verify_checksum — added there after adversarial review found the original
# script downloaded and installed the archive with no integrity check at
# all. checksums.txt uses the same "<sha256>  <filename>" line shape for
# every platform in the release, so the same parse works here unchanged.
function Test-Checksum {
    param(
        [Parameter(Mandatory)][string]$ArchivePath,
        [Parameter(Mandatory)][string]$ArchiveName,
        [Parameter(Mandatory)][string]$ChecksumsFile
    )
    $pattern = '^([0-9a-fA-F]{64})\s+' + [regex]::Escape($ArchiveName) + '$'
    $match = Select-String -Path $ChecksumsFile -Pattern $pattern | Select-Object -First 1
    if (-not $match) {
        throw "no checksum entry found for $ArchiveName in checksums.txt"
    }
    $expected = $match.Matches[0].Groups[1].Value.ToLowerInvariant()
    $actual = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "checksum mismatch for ${ArchiveName}: expected $expected, got $actual — refusing to install a tampered or corrupted download"
    }
}

# Add-InstallDirToUserPath appends $Dir to the persistent per-user PATH
# (registry-backed, survives reboots/new shells) if it isn't already there,
# and also updates $env:Path for the *current* process — the registry write
# alone would not take effect until a new shell is opened, so without this
# second step 'damping version' would not work immediately after install,
# unlike install.sh's outcome where a plain POSIX PATH is already live in
# the same shell.
#
# Goes through the raw registry API rather than
# [Environment]::GetEnvironmentVariable/SetEnvironmentVariable, which is a
# known footgun: it always reads the EXPANDED value and always writes back
# as REG_SZ, so a user PATH stored as REG_EXPAND_SZ (containing %VARS%, e.g.
# a chocolatey or corporate-policy PATH entry) gets silently and
# irreversibly rewritten into REG_SZ with those variables baked in as dead
# literal text the first time this script runs. Reading raw + writing back
# with the ORIGINAL RegistryValueKind avoids that. $EnvironmentKeyPath is
# overridable so the exact same function can be exercised against a
# throwaway HKCU subkey in tests instead of the real Environment key.
function Add-InstallDirToUserPath {
    param(
        [Parameter(Mandatory)][string]$Dir,
        [string]$EnvironmentKeyPath = 'Environment'
    )

    $normalizedDir = $Dir.TrimEnd('\')

    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($EnvironmentKeyPath, $true)
    if (-not $key) {
        throw "registry key not found: HKCU\$EnvironmentKeyPath"
    }
    try {
        $hasPathValue = $key.GetValueNames() -contains 'Path'
        $rawUserPath = if ($hasPathValue) {
            $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        } else {
            ''
        }
        $valueKind = if ($hasPathValue) { $key.GetValueKind('Path') } else { [Microsoft.Win32.RegistryValueKind]::String }

        # Dedupe against both the raw entries (so e.g. "%FOO%\bin" isn't
        # re-added verbatim on a re-run) and the expanded ones (so an
        # already-present expanded equivalent of $Dir is also recognized) —
        # a REG_EXPAND_SZ PATH mixes literal and %VAR% entries freely.
        # @(...) around each pipeline is load-bearing, not decorative: if a
        # pipeline yields exactly one match, PowerShell assigns that single
        # object unwrapped (scalar), not as a 1-element array. Without the
        # @(...), a one-entry PATH turns "$rawEntries + $expandedEntries"
        # from array concatenation into silent STRING concatenation (e.g.
        # '%SystemRoot%' + 'C:\Windows' -> '%SystemRoot%C:\Windows'), which
        # never matches $normalizedDir and defeats the dedupe check entirely.
        $rawEntries = @()
        if ($rawUserPath) {
            $rawEntries = @($rawUserPath -split ';' | Where-Object { $_ -ne '' })
        }
        $expandedUserPath = [Environment]::ExpandEnvironmentVariables($rawUserPath)
        $expandedEntries = @()
        if ($expandedUserPath) {
            $expandedEntries = @($expandedUserPath -split ';' | Where-Object { $_ -ne '' })
        }
        $alreadyInUserPath = ($rawEntries + $expandedEntries) | Where-Object { $_.TrimEnd('\') -ieq $normalizedDir }
        if (-not $alreadyInUserPath) {
            $newUserPath = if ($rawUserPath -and $rawUserPath.TrimEnd(';') -ne '') { "$($rawUserPath.TrimEnd(';'));$Dir" } else { $Dir }
            $key.SetValue('Path', $newUserPath, $valueKind)
        }
    } finally {
        $key.Close()
    }

    $sessionEntries = @()
    if ($env:Path) {
        $sessionEntries = $env:Path -split ';' | Where-Object { $_ -ne '' }
    }
    $alreadyInSession = $sessionEntries | Where-Object { $_.TrimEnd('\') -ieq $normalizedDir }
    if (-not $alreadyInSession) {
        $env:Path = if ($env:Path -and $env:Path.TrimEnd(';') -ne '') { "$($env:Path.TrimEnd(';'));$Dir" } else { $Dir }
    }
}

function Main {
    Test-SupportedArch

    $version = Resolve-DampingVersion
    $versionNum = $version.TrimStart('v')

    $archive = "damping_${versionNum}_windows_amd64.zip"
    $baseUrl = "https://github.com/$Repo/releases/download/$version"
    $headers = @{ "User-Agent" = "damping-installer" }

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "damping-install-$([Guid]::NewGuid())"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    try {
        $archivePath = Join-Path $tmpDir $archive
        $checksumsPath = Join-Path $tmpDir "checksums.txt"

        Write-Info "Downloading damping $version for windows/amd64..."
        try {
            Invoke-WebRequest -Uri "$baseUrl/$archive" -OutFile $archivePath -Headers $headers
        } catch {
            throw "download failed: $baseUrl/$archive"
        }
        try {
            Invoke-WebRequest -Uri "$baseUrl/checksums.txt" -OutFile $checksumsPath -Headers $headers
        } catch {
            throw "downloading checksums.txt failed: $baseUrl/checksums.txt"
        }

        Test-Checksum -ArchivePath $archivePath -ArchiveName $archive -ChecksumsFile $checksumsPath

        $extractDir = Join-Path $tmpDir "extracted"
        Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force

        $binaryPath = Join-Path $extractDir "damping.exe"
        if (-not (Test-Path $binaryPath)) {
            throw "damping.exe not found inside $archive — archive layout may have changed"
        }

        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        $finalBinaryPath = Join-Path $InstallDir "damping.exe"

        # Windows locks a running executable's image against delete/replace
        # but allows renaming it, so a plain `Move-Item -Force` straight onto
        # $finalBinaryPath fails every time this script runs as a self-update
        # (`damping update`, the dashboard's update button) while damping.exe
        # is the process doing the updating. Rename the old binary out of the
        # way first — that succeeds even while it's executing — then move the
        # new one into place, then best-effort delete the old one (it stays
        # locked for as long as the old process lives, so failure here is
        # expected and handled by the stale-.old cleanup at script start).
        if (Test-Path $finalBinaryPath) {
            $oldBinaryPath = "$finalBinaryPath.old"
            Move-Item -Path $finalBinaryPath -Destination $oldBinaryPath -Force
            Move-Item -Path $binaryPath -Destination $finalBinaryPath -Force
            Remove-Item -Path $oldBinaryPath -Force -ErrorAction SilentlyContinue
        } else {
            Move-Item -Path $binaryPath -Destination $finalBinaryPath -Force
        }

        Add-InstallDirToUserPath -Dir $InstallDir

        Write-Info "✓ damping $version installed to $finalBinaryPath"
        Write-Info "  Run 'damping init' to get started."
    } finally {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

try {
    Main
} catch {
    # `exit` here would kill the whole host process, not just this script —
    # fatal when run the README-advertised way (`irm ... | iex`), since iex
    # runs script content in the CALLER's session scope. `throw` still gives
    # a script caller a terminating error (and a non-zero process exit code
    # under `-File`), but an interactive session survives to see the message
    # and get its prompt back, same as any other uncaught PowerShell error.
    [Console]::Error.WriteLine("damping: $($_.Exception.Message)")
    throw
}
