#!/bin/sh
# AutomateSTIG installer for macOS.
#   curl -fsSL https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/main/install-macos.sh | sh
set -e

REPO="ibadukefan/AutomateSTIG"
API_URL="https://api.github.com/repos/$REPO/releases/latest"
TARGET_OS="apple-darwin"

err() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"
}

[ "$(uname -s 2>/dev/null || true)" = "Darwin" ] || err "this installer is for macOS; on Linux use install-linux.sh"

ARCH="$(uname -m 2>/dev/null || true)"
case "$ARCH" in
  x86_64 | amd64) TARGET_ARCH="x86_64" ;;
  arm64 | aarch64) TARGET_ARCH="aarch64" ;;
  *) err "unsupported architecture: ${ARCH:-unknown}" ;;
esac

TARGET="$TARGET_ARCH-$TARGET_OS"

need_cmd awk
need_cmd curl
need_cmd cosign
need_cmd grep
need_cmd tar
need_cmd tr

if [ -n "${AUTOMATESTIG_VERSION:-}" ]; then
  TAG="$AUTOMATESTIG_VERSION"
else
  printf 'Resolving latest AutomateSTIG release...\n'
  LATEST_JSON="$(curl --proto '=https' --proto-redir '=https' -fsSL "$API_URL")" ||
    err "failed to query $API_URL"
  TAG="$(printf '%s\n' "$LATEST_JSON" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
fi

[ -n "$TAG" ] || err "could not determine release tag"
printf '%s\n' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$' ||
  err "invalid release tag: $TAG"

ARCHIVE_NAME="automatestig-$TAG-$TARGET.tar.gz"
CHECKSUM_NAME="$ARCHIVE_NAME.sha256"
BUNDLE_NAME="$ARCHIVE_NAME.sigstore.bundle"
DOWNLOAD_BASE="https://github.com/$REPO/releases/download/$TAG"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/automatestig.XXXXXX")" || err "failed to create temporary directory"

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT HUP INT TERM

ARCHIVE_PATH="$TMP_DIR/$ARCHIVE_NAME"
CHECKSUM_PATH="$TMP_DIR/$CHECKSUM_NAME"
BUNDLE_PATH="$TMP_DIR/$BUNDLE_NAME"
EXTRACT_DIR="$TMP_DIR/extract"

printf 'Downloading AutomateSTIG %s for %s...\n' "$TAG" "$TARGET"
curl --proto '=https' --proto-redir '=https' -fL --retry 3 --connect-timeout 15 -o "$ARCHIVE_PATH" "$DOWNLOAD_BASE/$ARCHIVE_NAME" ||
  err "failed to download $ARCHIVE_NAME"
curl --proto '=https' --proto-redir '=https' -fL --retry 3 --connect-timeout 15 -o "$CHECKSUM_PATH" "$DOWNLOAD_BASE/$CHECKSUM_NAME" ||
  err "failed to download $CHECKSUM_NAME"
curl --proto '=https' --proto-redir '=https' -fL --retry 3 --connect-timeout 15 -o "$BUNDLE_PATH" "$DOWNLOAD_BASE/$BUNDLE_NAME" ||
  err "failed to download $BUNDLE_NAME"

printf 'Verifying SHA-256 checksum...\n'
CHECKSUM_RECORD="$(awk 'NF { count += 1; record = $0 } END { if (count == 1) print record }' "$CHECKSUM_PATH")"
set -- $CHECKSUM_RECORD
[ "$#" -eq 2 ] || err "$CHECKSUM_NAME must contain exactly one checksum record"
EXPECTED_HASH="$1"
[ "$2" = "$ARCHIVE_NAME" ] || err "$CHECKSUM_NAME does not name $ARCHIVE_NAME"
case "$EXPECTED_HASH" in
  *[!0-9A-Fa-f]* | '') err "$CHECKSUM_NAME contains an invalid SHA-256 digest" ;;
esac
[ "${#EXPECTED_HASH}" -eq 64 ] || err "$CHECKSUM_NAME contains an invalid SHA-256 digest"
if command -v shasum >/dev/null 2>&1; then
  ACTUAL_HASH="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_HASH="$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')"
else
  err "required command not found: shasum or sha256sum"
fi
[ "$(printf '%s' "$EXPECTED_HASH" | tr 'A-F' 'a-f')" = "$(printf '%s' "$ACTUAL_HASH" | tr 'A-F' 'a-f')" ] ||
  err "checksum verification failed for $ARCHIVE_NAME"

printf 'Verifying keyless Sigstore signature...\n'
IDENTITY="https://github.com/$REPO/.github/workflows/ci.yml@refs/tags/$TAG"
COSIGN_EXPERIMENTAL=1 cosign verify-blob \
  --bundle "$BUNDLE_PATH" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARCHIVE_PATH" >/dev/null || err "Sigstore verification failed for $ARCHIVE_NAME"

mkdir -p "$EXTRACT_DIR"
tar -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR" || err "failed to extract $ARCHIVE_NAME"

if [ -n "${AUTOMATESTIG_INSTALL_DIR:-}" ]; then
  INSTALL_DIR="$AUTOMATESTIG_INSTALL_DIR"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  INSTALL_DIR="/usr/local/bin"
else
  [ -n "${HOME:-}" ] || err "HOME is not set; set AUTOMATESTIG_INSTALL_DIR"
  INSTALL_DIR="$HOME/.local/bin"
fi

mkdir -p "$INSTALL_DIR" || err "failed to create install directory: $INSTALL_DIR"
[ -w "$INSTALL_DIR" ] || err "install directory is not writable: $INSTALL_DIR"

for BIN in automatestig automatestig-gui; do
  SRC="$EXTRACT_DIR/$BIN"
  [ -f "$SRC" ] || err "$BIN not found in $ARCHIVE_NAME"
  cp "$SRC" "$INSTALL_DIR/$BIN" || err "failed to install $BIN"
  chmod +x "$INSTALL_DIR/$BIN" || err "failed to mark $BIN executable"
done

printf 'Installed AutomateSTIG %s to %s\n' "$TAG" "$INSTALL_DIR"
case ":${PATH:-}:" in
  *:"$INSTALL_DIR":*) ;;
  *) printf 'Add %s to your PATH to run AutomateSTIG from a new shell.\n' "$INSTALL_DIR" ;;
esac
printf 'Launch the GUI with: automatestig-gui\n'
printf 'CLI help: automatestig --help\n'
