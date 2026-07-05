#!/bin/sh
# Damping install script — see docs/開發計畫.md §1.4 ("一行script：curl
# -sSL https://rein.dev/install | sh（偵測OS/arch下載對應binary）") and
# README.md's Quick Start, which already advertises
# "curl -sSL https://damping.dev/install | sh". Downloads the pre-built
# binary matching the current OS/arch from a GitHub Release (built by
# .goreleaser.yaml at the repo root) and installs it onto $PATH.
#
# POSIX sh, not bash — users pipe this straight from curl without
# controlling which shell interprets it, and macOS's default /bin/sh is
# not bash, so this must run correctly under a strict POSIX shell.
#
# Override with environment variables:
#   DAMPING_VERSION=v1.2.3    install a specific tag instead of latest
#   DAMPING_INSTALL_DIR=~/bin install somewhere other than /usr/local/bin
set -eu

REPO="amplify-lab/damping"
INSTALL_DIR="${DAMPING_INSTALL_DIR:-/usr/local/bin}"
VERSION="${DAMPING_VERSION:-}"

log() { printf '%s\n' "$*" >&2; }
die() {
	log "damping: $*"
	exit 1
}

detect_os() {
	case "$(uname -s)" in
	Linux) echo linux ;;
	Darwin) echo darwin ;;
	*) die "unsupported OS: $(uname -s) — only linux and darwin have pre-built binaries (see docs/cli-reference.md)" ;;
	esac
}

detect_arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	arm64 | aarch64) echo arm64 ;;
	*) die "unsupported architecture: $(uname -m)" ;;
	esac
}

# resolve_version prints the exact tag to install (e.g. "v1.2.3"), either
# from $DAMPING_VERSION or by asking the GitHub API for the latest release
# — deliberately not the simpler "/releases/latest/download/<fixed-name>"
# redirect trick, since .goreleaser.yaml's archive names include the
# version (letting users pin an exact version is worth the one extra
# request, and avoids depending on jq being installed).
resolve_version() {
	if [ -n "$VERSION" ]; then
		printf '%s\n' "$VERSION"
		return
	fi
	tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
		| grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
	[ -n "$tag" ] || die "could not resolve the latest release version from the GitHub API"
	printf '%s\n' "$tag"
}

main() {
	command -v curl >/dev/null 2>&1 || die "curl is required"
	command -v tar >/dev/null 2>&1 || die "tar is required"

	os=$(detect_os)
	arch=$(detect_arch)
	version=$(resolve_version)
	version_num=${version#v}

	archive="damping_${version_num}_${os}_${arch}.tar.gz"
	url="https://github.com/${REPO}/releases/download/${version}/${archive}"

	tmp_dir=$(mktemp -d)
	trap 'rm -rf "$tmp_dir"' EXIT INT TERM

	log "Downloading damping ${version} for ${os}/${arch}..."
	curl -fsSL "$url" -o "${tmp_dir}/${archive}" || die "download failed: $url"

	tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir" damping

	mkdir -p "$INSTALL_DIR"
	if [ -w "$INSTALL_DIR" ]; then
		mv "${tmp_dir}/damping" "${INSTALL_DIR}/damping"
	else
		log "Installing to ${INSTALL_DIR} requires sudo..."
		sudo mv "${tmp_dir}/damping" "${INSTALL_DIR}/damping"
	fi
	chmod +x "${INSTALL_DIR}/damping"

	log "✓ damping ${version} installed to ${INSTALL_DIR}/damping"
	log "  Run 'damping init' to get started."
}

main "$@"
