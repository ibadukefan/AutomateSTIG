#!/bin/sh
# AutomateSTIG installer for Linux.
# Download this script from the exact release tag, verify that immutable GitHub
# release first, then run it with AUTOMATESTIG_VERSION set to the same tag.
set -e

REPO="ibadukefan/AutomateSTIG"
API_URL="https://api.github.com/repos/$REPO/releases/latest"
TARGET_OS="unknown-linux-gnu"

err() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"
}

[ "$(uname -s 2>/dev/null || true)" = "Linux" ] || err "this installer is for Linux; on macOS use install-macos.sh"

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
need_cmd python3
need_cmd tar
need_cmd tr

python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' ||
  err "Python 3.10 or newer is required by automatestig-backup-restore"

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

INSTALL_TXN_DIR=
TRANSACTION_ACTIVE=0
MOVED_CLI=0
MOVED_GUI=0
MOVED_BACKUP_TOOL=0
INSTALLED_CLI=0
INSTALLED_GUI=0
INSTALLED_BACKUP_TOOL=0

path_exists() {
  [ -e "$1" ] || [ -L "$1" ]
}

rollback_install() {
  [ "$TRANSACTION_ACTIVE" -eq 1 ] || return 0
  printf 'Rolling back incomplete AutomateSTIG installation...\n' >&2
  rollback_status=0
  if [ "$INSTALLED_CLI" -eq 1 ]; then
    rm -f "$INSTALL_DIR/automatestig" || rollback_status=1
  fi
  if [ "$INSTALLED_GUI" -eq 1 ]; then
    rm -f "$INSTALL_DIR/automatestig-gui" || rollback_status=1
  fi
  if [ "$INSTALLED_BACKUP_TOOL" -eq 1 ]; then
    rm -f "$INSTALL_DIR/automatestig-backup-restore" || rollback_status=1
  fi
  if [ "$MOVED_CLI" -eq 1 ] && path_exists "$INSTALL_TXN_DIR/backup/automatestig"; then
    mv "$INSTALL_TXN_DIR/backup/automatestig" "$INSTALL_DIR/automatestig" ||
      rollback_status=1
  fi
  if [ "$MOVED_GUI" -eq 1 ] && path_exists "$INSTALL_TXN_DIR/backup/automatestig-gui"; then
    mv "$INSTALL_TXN_DIR/backup/automatestig-gui" "$INSTALL_DIR/automatestig-gui" ||
      rollback_status=1
  fi
  if [ "$MOVED_BACKUP_TOOL" -eq 1 ] && path_exists "$INSTALL_TXN_DIR/backup/automatestig-backup-restore"; then
    mv "$INSTALL_TXN_DIR/backup/automatestig-backup-restore" "$INSTALL_DIR/automatestig-backup-restore" ||
      rollback_status=1
  fi
  if [ "$rollback_status" -eq 0 ]; then
    TRANSACTION_ACTIVE=0
  fi
  return "$rollback_status"
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  if rollback_install; then
    [ -z "$INSTALL_TXN_DIR" ] || rm -rf "$INSTALL_TXN_DIR"
  else
    status=1
    printf 'error: rollback failed; prior binaries are preserved in %s/backup\n' \
      "$INSTALL_TXN_DIR" >&2
  fi
  rm -rf "$TMP_DIR"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_HASH="$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_HASH="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
else
  err "required command not found: sha256sum or shasum"
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

printf 'Validating the closed release archive member set...\n'
python3 - "$ARCHIVE_PATH" <<'PY' || err "unsafe or unexpected members in $ARCHIVE_NAME"
import pathlib
import sys
import tarfile

expected = {
    "automatestig",
    "automatestig-gui",
    "automatestig-backup-restore",
    "README.md",
    "LICENSE",
    "quickstart.md",
    "installation.md",
}
seen = set()
total = 0
with tarfile.open(sys.argv[1], mode="r:gz") as archive:
    members = archive.getmembers()
    for member in members:
        name = member.name
        path = pathlib.PurePosixPath(name)
        if (
            name not in expected
            or name in seen
            or path.is_absolute()
            or any(part in ("", ".", "..") for part in path.parts)
            or not member.isfile()
            or member.size < 0
            or member.size > 300 * 1024 * 1024
            or member.mode & 0o7000
        ):
            raise SystemExit(f"rejected archive member: {name!r}")
        seen.add(name)
        total += member.size
    if seen != expected:
        raise SystemExit(f"release member mismatch: missing={sorted(expected - seen)}")
    if total > 650 * 1024 * 1024:
        raise SystemExit("release archive expands beyond the permitted total")
PY

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

INSTALL_TXN_DIR="$(mktemp -d "$INSTALL_DIR/.automatestig-install.XXXXXX")" ||
  err "failed to create install transaction in $INSTALL_DIR"
mkdir -p "$INSTALL_TXN_DIR/stage" "$INSTALL_TXN_DIR/backup" ||
  err "failed to prepare install transaction"

for BIN in automatestig automatestig-gui automatestig-backup-restore; do
  SRC="$EXTRACT_DIR/$BIN"
  [ -f "$SRC" ] && [ ! -L "$SRC" ] || err "$BIN is not a regular file in $ARCHIVE_NAME"
  cp "$SRC" "$INSTALL_TXN_DIR/stage/$BIN" || err "failed to stage $BIN"
  chmod 0755 "$INSTALL_TXN_DIR/stage/$BIN" || err "failed to stage executable $BIN"
done

# Remove the old entry points before publishing any new one. Each move is
# within INSTALL_DIR and therefore atomic; an error or catchable interruption
# restores the complete prior toolset instead of leaving old/new files mixed.
TRANSACTION_ACTIVE=1
if path_exists "$INSTALL_DIR/automatestig"; then
  MOVED_CLI=1
  mv "$INSTALL_DIR/automatestig" "$INSTALL_TXN_DIR/backup/automatestig" ||
    err "failed to preserve existing automatestig"
fi
if path_exists "$INSTALL_DIR/automatestig-gui"; then
  MOVED_GUI=1
  mv "$INSTALL_DIR/automatestig-gui" "$INSTALL_TXN_DIR/backup/automatestig-gui" ||
    err "failed to preserve existing automatestig-gui"
fi
if path_exists "$INSTALL_DIR/automatestig-backup-restore"; then
  MOVED_BACKUP_TOOL=1
  mv "$INSTALL_DIR/automatestig-backup-restore" "$INSTALL_TXN_DIR/backup/automatestig-backup-restore" ||
    err "failed to preserve existing automatestig-backup-restore"
fi
INSTALLED_CLI=1
mv "$INSTALL_TXN_DIR/stage/automatestig" "$INSTALL_DIR/automatestig" ||
  err "failed to publish automatestig"
INSTALLED_GUI=1
mv "$INSTALL_TXN_DIR/stage/automatestig-gui" "$INSTALL_DIR/automatestig-gui" ||
  err "failed to publish automatestig-gui"
INSTALLED_BACKUP_TOOL=1
mv "$INSTALL_TXN_DIR/stage/automatestig-backup-restore" "$INSTALL_DIR/automatestig-backup-restore" ||
  err "failed to publish automatestig-backup-restore"
TRANSACTION_ACTIVE=0
rm -rf "$INSTALL_TXN_DIR"
INSTALL_TXN_DIR=

printf 'Installed AutomateSTIG %s to %s\n' "$TAG" "$INSTALL_DIR"
case ":${PATH:-}:" in
  *:"$INSTALL_DIR":*) ;;
  *) printf 'Add %s to your PATH to run AutomateSTIG from a new shell.\n' "$INSTALL_DIR" ;;
esac
printf 'Launch the GUI with: automatestig-gui\n'
printf 'CLI help: automatestig --help\n'
printf 'State recovery help: automatestig-backup-restore --help\n'
