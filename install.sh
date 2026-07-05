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

# verify_checksum confirms archive_path really is the exact file
# .goreleaser.yaml's checksum step recorded for archive_name in the same
# release, failing loudly rather than installing an unverified binary.
# Found missing entirely via adversarial review: this script downloaded and
# installed the archive with no integrity check at all — anyone able to
# tamper with the download in transit (a compromised CDN edge, a
# TLS-terminating proxy) got their payload installed silently, sometimes via
# sudo. sha256sum (Linux) and shasum (macOS's actual default; it has no
# sha256sum) produce the same "<hash>  <filename>" line shape .goreleaser.yaml's
# checksums.txt uses, so either can check a single extracted line directly.
verify_checksum() {
	archive_path=$1
	archive_name=$2
	checksums_file=$3

	line=$(grep " ${archive_name}\$" "$checksums_file" || true)
	[ -n "$line" ] || die "no checksum entry found for ${archive_name} in checksums.txt"
	expected=$(printf '%s\n' "$line" | awk '{print $1}')

	if command -v sha256sum >/dev/null 2>&1; then
		actual=$(sha256sum "$archive_path" | awk '{print $1}')
	elif command -v shasum >/dev/null 2>&1; then
		actual=$(shasum -a 256 "$archive_path" | awk '{print $1}')
	else
		die "need sha256sum or shasum to verify the downloaded archive"
	fi

	[ "$expected" = "$actual" ] || die "checksum mismatch for ${archive_name}: expected ${expected}, got ${actual} — refusing to install a tampered or corrupted download"
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
	base_url="https://github.com/${REPO}/releases/download/${version}"

	tmp_dir=$(mktemp -d)
	trap 'rm -rf "$tmp_dir"' EXIT INT TERM

	log "Downloading damping ${version} for ${os}/${arch}..."
	curl -fsSL "${base_url}/${archive}" -o "${tmp_dir}/${archive}" || die "download failed: ${base_url}/${archive}"
	curl -fsSL "${base_url}/checksums.txt" -o "${tmp_dir}/checksums.txt" || die "downloading checksums.txt failed: ${base_url}/checksums.txt"

	verify_checksum "${tmp_dir}/${archive}" "$archive" "${tmp_dir}/checksums.txt"

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
