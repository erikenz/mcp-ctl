#!/bin/sh
# Install mcp-ctl from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/erikenz/mcp-ctl/main/install/install.sh | sh
#
#   --version <x.y.z>   release to install (default: the latest)
#   --to <dir>          where to put the binary (default: ~/.local/bin)
#
# The download is verified against the release's .sha256 before anything is
# installed, and nothing is written outside the destination directory.
set -eu

REPO="erikenz/mcp-ctl"
VERSION=""
DEST="${MCP_CTL_INSTALL_DIR:-${HOME}/.local/bin}"
BASE_URL="${MCP_CTL_DOWNLOAD_URL:-https://github.com/${REPO}/releases/download}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
mcp-ctl installer

  --version <x.y.z>   release to install (default: the latest)
  --to <dir>          where to put the binary (default: ~/.local/bin)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; [ -n "$VERSION" ] || die "--version needs a value"; shift 2 ;;
    --to) DEST="${2:-}"; [ -n "$DEST" ] || die "--to needs a value"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

command -v curl > /dev/null || die "curl is required"
command -v tar > /dev/null || die "tar is required"

# Work out which archive this machine needs.
case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported system: $(uname -s). On Windows, use install.ps1" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

if [ "$os" = linux ]; then
  target="${arch}-unknown-linux-musl"
else
  target="${arch}-apple-darwin"
fi

# "latest" resolves through GitHub's redirect: no API token, no rate limit, no jq.
if [ -z "$VERSION" ]; then
  resolved=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest") \
    || die "could not reach github.com to find the latest release"
  case "$resolved" in
    */tag/v*) VERSION=${resolved##*/tag/v} ;;
    *) die "could not work out the latest version from '$resolved'" ;;
  esac
fi

# The version becomes part of a URL and a file path. Releases are x.y.z, so reject
# anything else instead of building a surprising path from a tag.
printf '%s\n' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || die "invalid version '$VERSION': expected a release version such as 1.2.3"

archive="mcp-ctl-${VERSION}-${target}.tar.gz"
url="${BASE_URL}/v${VERSION}/${archive}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading ${archive}"
curl -fsSL "$url" -o "$tmp/$archive" || die "download failed: $url"
curl -fsSL "${url}.sha256" -o "$tmp/$archive.sha256" || die "checksum download failed: ${url}.sha256"

if command -v sha256sum > /dev/null; then
  ( cd "$tmp" && sha256sum -c "$archive.sha256" > /dev/null ) || die "checksum mismatch for ${archive}"
elif command -v shasum > /dev/null; then
  ( cd "$tmp" && shasum -a 256 -c "$archive.sha256" > /dev/null ) || die "checksum mismatch for ${archive}"
else
  die "neither sha256sum nor shasum is available to verify the download"
fi

tar -xzf "$tmp/$archive" -C "$tmp" || die "could not unpack ${archive}"
[ -f "$tmp/mcp-ctl" ] || die "the archive does not contain mcp-ctl"

mkdir -p "$DEST" || die "could not create ${DEST}"
if command -v install > /dev/null; then
  install -m 755 "$tmp/mcp-ctl" "$DEST/mcp-ctl"
else
  cp "$tmp/mcp-ctl" "$DEST/mcp-ctl" && chmod 755 "$DEST/mcp-ctl"
fi

say "Installed to ${DEST}/mcp-ctl"
say "Update later with: mcp-ctl update"
case ":${PATH}:" in
  *":${DEST}:"*) ;;
  *) say "Note: ${DEST} is not on your PATH. Add it, or rerun with --to somewhere that is." ;;
esac
