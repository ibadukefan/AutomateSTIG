#!/bin/sh
# AutomateSTIG installer for macOS.
#   curl -fsSL https://raw.githubusercontent.com/ibadukefan/AutomateSTIG/claude/build-automatestig-cJqhi/install-macos.sh | sh
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

need_cmd curl
need_cmd tar

if [ -n "${AUTOMATESTIG_VERSION:-}" ]; then
  TAG="$AUTOMATESTIG_VERSION"
else
  printf 'Resolving latest AutomateSTIG release...\n'
  LATEST_JSON="$(curl -fsSL "$API_URL")" || err "failed to query $API_URL"
  TAG="$(printf '%s\n' "$LATEST_JSON" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
fi

[ -n "$TAG" ] || err "could not determine release tag"

ARCHIVE_NAME="automatestig-$TAG-$TARGET.tar.gz"
CHECKSUM_NAME="automatestig-$TAG-$TARGET.sha256"
DOWNLOAD_BASE="https://github.com/$REPO/releases/download/$TAG"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/automatestig.XXXXXX")" || err "failed to create temporary directory"

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT HUP INT TERM

ARCHIVE_PATH="$TMP_DIR/$ARCHIVE_NAME"
CHECKSUM_PATH="$TMP_DIR/$CHECKSUM_NAME"
EXTRACT_DIR="$TMP_DIR/extract"

printf 'Downloading AutomateSTIG %s for %s...\n' "$TAG" "$TARGET"
curl -fL --retry 3 --connect-timeout 15 -o "$ARCHIVE_PATH" "$DOWNLOAD_BASE/$ARCHIVE_NAME" ||
  err "failed to download $ARCHIVE_NAME"
curl -fL --retry 3 --connect-timeout 15 -o "$CHECKSUM_PATH" "$DOWNLOAD_BASE/$CHECKSUM_NAME" ||
  err "failed to download $CHECKSUM_NAME"

printf 'Verifying SHA-256 checksum...\n'
if command -v shasum >/dev/null 2>&1; then
  (cd "$TMP_DIR" && shasum -a 256 -c "$CHECKSUM_NAME") || err "checksum verification failed for $ARCHIVE_NAME"
elif command -v sha256sum >/dev/null 2>&1; then
  (cd "$TMP_DIR" && sha256sum -c "$CHECKSUM_NAME") || err "checksum verification failed for $ARCHIVE_NAME"
else
  err "required command not found: shasum or sha256sum"
fi

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
  # The binaries are not notarized; clear the quarantine flag so Gatekeeper allows them.
  command -v xattr >/dev/null 2>&1 && xattr -d com.apple.quarantine "$INSTALL_DIR/$BIN" 2>/dev/null || true
done

printf 'Installed AutomateSTIG %s to %s\n' "$TAG" "$INSTALL_DIR"
case ":${PATH:-}:" in
  *:"$INSTALL_DIR":*) ;;
  *) printf 'Add %s to your PATH to run AutomateSTIG from a new shell.\n' "$INSTALL_DIR" ;;
esac
printf 'Launch the GUI with: automatestig-gui\n'
printf 'CLI help: automatestig --help\n'
