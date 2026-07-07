#!/bin/sh
set -e

REPO="ibadukefan/AutomateSTIG"
API_URL="https://api.github.com/repos/$REPO/releases/latest"

err() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"
}

OS="$(uname -s 2>/dev/null || true)"
case "$OS" in
  Darwin)
    TARGET_OS="apple-darwin"
    ;;
  Linux)
    TARGET_OS="unknown-linux-gnu"
    ;;
  *)
    err "unsupported operating system: ${OS:-unknown}"
    ;;
esac

ARCH="$(uname -m 2>/dev/null || true)"
case "$ARCH" in
  x86_64 | amd64)
    TARGET_ARCH="x86_64"
    ;;
  arm64 | aarch64)
    TARGET_ARCH="aarch64"
    ;;
  *)
    err "unsupported architecture: ${ARCH:-unknown}"
    ;;
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
TMP_PARENT="${TMPDIR:-/tmp}"
TMP_DIR="$(mktemp -d "$TMP_PARENT/automatestig.XXXXXX")" || err "failed to create temporary directory"

cleanup() {
  rm -rf "$TMP_DIR"
}
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
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$TMP_DIR" && sha256sum -c "$CHECKSUM_NAME") ||
    err "checksum verification failed for $ARCHIVE_NAME"
elif command -v shasum >/dev/null 2>&1; then
  (cd "$TMP_DIR" && shasum -a 256 -c "$CHECKSUM_NAME") ||
    err "checksum verification failed for $ARCHIVE_NAME"
else
  err "required command not found: sha256sum or shasum"
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
done

if [ "$TARGET_OS" = "apple-darwin" ] && command -v xattr >/dev/null 2>&1; then
  xattr -d com.apple.quarantine "$INSTALL_DIR/automatestig" 2>/dev/null || true
  xattr -d com.apple.quarantine "$INSTALL_DIR/automatestig-gui" 2>/dev/null || true
fi

printf 'Installed AutomateSTIG %s to %s\n' "$TAG" "$INSTALL_DIR"
case ":${PATH:-}:" in
  *:"$INSTALL_DIR":*)
    ;;
  *)
    printf 'Add %s to your PATH to run AutomateSTIG from a new shell.\n' "$INSTALL_DIR"
    ;;
esac
printf 'Launch the GUI with: automatestig-gui\n'
printf 'CLI help: automatestig --help\n'
