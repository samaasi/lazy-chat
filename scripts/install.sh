#!/bin/sh
# Install lazy-chat on macOS or Linux:
#
#   curl -fsSL https://raw.githubusercontent.com/samaasi/lazy-chat/master/scripts/install.sh | sh
#
# It downloads the release for this machine, checks it against the release's
# SHA-256 checksums and, when openssl is available, the checksums' signature,
# then puts `lazy-chat` in place. Nothing is installed if a check fails.
#
# Options (environment variables):
#   LAZYCHAT_VERSION      version to install, e.g. v1.2.3 (default: the latest)
#   LAZYCHAT_INSTALL_DIR  where to put it (default: /usr/local/bin if writable,
#                         else ~/.local/bin)
#   LAZYCHAT_REPO         owner/name on GitHub (default: samaasi/lazy-chat)
#   LAZYCHAT_BASE_URL     release download root (default: https://github.com/<repo>/releases)
#   LAZYCHAT_KEY_URL      where to fetch the release public key
#   LAZYCHAT_ALLOW_UNSIGNED=1  install even though the signature cannot be checked

set -eu

repo="${LAZYCHAT_REPO:-samaasi/lazy-chat}"
base="${LAZYCHAT_BASE_URL:-https://github.com/${repo}/releases}"

say() { printf '%s\n' "$*"; }
fail() { printf 'install: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have curl || fail "curl is required"
have tar || fail "tar is required"

# ---- Which build? ------------------------------------------------------------
case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported system $(uname -s); on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "unsupported CPU $(uname -m)" ;;
esac

# ---- Which version? ----------------------------------------------------------
tag="${LAZYCHAT_VERSION:-}"
if [ -z "$tag" ]; then
  # /releases/latest redirects to /releases/tag/<tag>.
  final=$(curl -fsSL -o /dev/null -w '%{url_effective}' "${base}/latest") || fail "could not look up the latest release"
  tag="${final##*/}"
fi
case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "unexpected version '$tag'" ;;
esac
version="${tag#v}"
archive="lazy-chat_${version}_${os}_${arch}.tar.gz"
url="${base}/download/${tag}"

# ---- Where to? ---------------------------------------------------------------
dir="${LAZYCHAT_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then
    dir=/usr/local/bin
  else
    dir="${HOME}/.local/bin"
  fi
fi
mkdir -p "$dir" 2>/dev/null || fail "cannot create $dir (set LAZYCHAT_INSTALL_DIR, or run with sudo)"
[ -w "$dir" ] || fail "cannot write to $dir (set LAZYCHAT_INSTALL_DIR, or run with sudo)"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t lazychat) || fail "cannot create a temporary directory"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Installing lazy-chat ${tag} (${os}/${arch}) to ${dir}"
curl -fsSL -o "$tmp/$archive" "${url}/${archive}" || fail "download failed: ${url}/${archive}"
curl -fsSL -o "$tmp/checksums.txt" "${url}/checksums.txt" || fail "download failed: ${url}/checksums.txt"

# ---- Verify ------------------------------------------------------------------
sha256_of() {
  if have sha256sum; then sha256sum "$1" | cut -d' ' -f1
  elif have shasum; then shasum -a 256 "$1" | cut -d' ' -f1
  elif have openssl; then openssl dgst -sha256 "$1" | sed 's/^.*= //'
  else fail "need sha256sum, shasum or openssl to verify the download"
  fi
}

verify_signature() {
  if ! curl -fsSL -o "$tmp/checksums.txt.sig" "${url}/checksums.txt.sig" 2>/dev/null; then
    return 1
  fi
  keyurl="${LAZYCHAT_KEY_URL:-https://raw.githubusercontent.com/${repo}/${tag}/internal/update/release.pub}"
  curl -fsSL -o "$tmp/release.pub" "$keyurl" 2>/dev/null || return 1
  grep -q 'BEGIN PUBLIC KEY' "$tmp/release.pub" || return 1
  have openssl || return 1
  openssl base64 -d -A -in "$tmp/checksums.txt.sig" -out "$tmp/sig.der" 2>/dev/null || fail "the release signature is malformed"
  if openssl dgst -sha256 -verify "$tmp/release.pub" -signature "$tmp/sig.der" "$tmp/checksums.txt" >/dev/null 2>&1; then
    return 0
  fi
  fail "the release signature does not match: refusing to install"
}

if verify_signature; then
  say "Signature verified."
elif [ "${LAZYCHAT_ALLOW_UNSIGNED:-}" = 1 ]; then
  say "Warning: could not verify the release signature (continuing because LAZYCHAT_ALLOW_UNSIGNED=1)."
else
  say "Note: the release signature could not be checked here (needs openssl and a signed release); relying on the SHA-256 checksum only."
fi

want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")
[ -n "$want" ] || fail "no checksum listed for $archive"
got=$(sha256_of "$tmp/$archive")
[ "$want" = "$got" ] || fail "checksum mismatch for $archive (expected $want, got $got): refusing to install"
say "Checksum verified."

# ---- Install -----------------------------------------------------------------
mkdir "$tmp/x"
tar -xzf "$tmp/$archive" -C "$tmp/x" lazy-chat 2>/dev/null || tar -xzf "$tmp/$archive" -C "$tmp/x" ./lazy-chat 2>/dev/null || fail "lazy-chat is not in the archive"
[ -s "$tmp/x/lazy-chat" ] || fail "lazy-chat is not in the archive"
chmod 755 "$tmp/x/lazy-chat"

# Copy next to the destination, then rename: the swap is atomic, so a running
# copy or an interrupted install never leaves a half-written file.
cp "$tmp/x/lazy-chat" "$dir/.lazy-chat.new.$$"
mv -f "$dir/.lazy-chat.new.$$" "$dir/lazy-chat"

say "Installed: $dir/lazy-chat"
case ":${PATH}:" in
  *":${dir}:"*) ;;
  *) say "Note: ${dir} is not on your PATH. Add it, e.g.  export PATH=\"${dir}:\$PATH\"" ;;
esac
say "Run 'lazy-chat --help' to get started. Update later with 'lazy-chat update'."
