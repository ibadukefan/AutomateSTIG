#!/bin/sh
# Unified AutomateSTIG installer for supported macOS and Linux releases.
#
# The default path is deliberately noninteractive: detect the host, install the
# release tag bound into this published script, and open the GUI. Every
# downloaded AutomateSTIG archive must pass both its bound SHA-256 checksum and
# its tagged-workflow Sigstore verification.
set -eu

REPO="ibadukefan/AutomateSTIG"
DEFAULT_INSTALL_DIR="${HOME:+$HOME/.local/bin}"
COSIGN_VERSION="v3.0.6"
MAX_PROGRAM_BYTES=314572800
MAX_PROGRAM_BLOCKS=614400
MAX_TOTAL_PROGRAM_BYTES=681574400
# Release CI replaces this exact token in the published installer asset. A
# checkout copy remains usable for maintainers only with an explicit --version.
SCRIPT_RELEASE_TAG="@AUTOMATESTIG_RELEASE_TAG@"

usage() {
  cat <<'EOF'
Install or upgrade AutomateSTIG for the current user. Download this script only
from a GitHub Release whose exact tag you verified with `gh release verify`.

Usage:
  install.sh [options]
  install.sh --uninstall [--install-dir DIR]

Options:
  --version TAG       Install an exact release, for example v0.3.0.
  --install-dir DIR   Install to an absolute directory (default: ~/.local/bin).
  --no-launch         Install without opening the GUI.
  --uninstall         Remove the three installed programs; keep user data.
  -h, --help          Show this help.

The installer never prompts, never uses sudo, never changes shell profiles, and
never disables checksum, Sigstore, or macOS Gatekeeper verification. Re-running
the same verified release installer safely repairs that version; download the
new verified release installer to upgrade.

Environment equivalents:
  AUTOMATESTIG_VERSION, AUTOMATESTIG_INSTALL_DIR,
  AUTOMATESTIG_NO_LAUNCH=1
EOF
}

err() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"
}

path_exists() {
  [ -e "$1" ] || [ -L "$1" ]
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    err "required command not found: sha256sum or shasum"
  fi
}

TAG="${AUTOMATESTIG_VERSION:-}"
INSTALL_DIR="${AUTOMATESTIG_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
NO_LAUNCH="${AUTOMATESTIG_NO_LAUNCH:-0}"
UNINSTALL=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || err "--version requires a release tag"
      TAG="$2"
      shift 2
      ;;
    --version=*)
      TAG=${1#*=}
      shift
      ;;
    --install-dir)
      [ "$#" -ge 2 ] || err "--install-dir requires an absolute directory"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --install-dir=*)
      INSTALL_DIR=${1#*=}
      shift
      ;;
    --no-launch)
      NO_LAUNCH=1
      shift
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *) err "unknown option: $1 (use --help)" ;;
  esac
done
[ "$#" -eq 0 ] || err "unexpected positional arguments (use --help)"

case "$SCRIPT_RELEASE_TAG" in
  v[0-9]*)
    if [ -n "$TAG" ] && [ "$TAG" != "$SCRIPT_RELEASE_TAG" ]; then
      err "this installer is bound to $SCRIPT_RELEASE_TAG and cannot install $TAG"
    fi
    TAG="$SCRIPT_RELEASE_TAG"
    ;;
  *)
    [ -n "$TAG" ] ||
      err "this repository copy is not a published installer; pass --version TAG for development testing or download install.sh from a verified GitHub Release"
    ;;
esac

case "$NO_LAUNCH" in 0 | 1) ;; *) err "AUTOMATESTIG_NO_LAUNCH must be 0 or 1" ;; esac
[ -n "$INSTALL_DIR" ] || err "HOME is not set; use --install-dir with an absolute directory"
case "$INSTALL_DIR" in
  /*) ;;
  *) err "install directory must be absolute: $INSTALL_DIR" ;;
esac
[ "$INSTALL_DIR" != "/" ] || err "refusing to use the filesystem root as the install directory"

if [ "$UNINSTALL" -eq 1 ]; then
  removed=0
  for program in automatestig automatestig-gui automatestig-backup-restore; do
    destination="$INSTALL_DIR/$program"
    if path_exists "$destination"; then
      rm -f "$destination" || err "failed to remove $destination"
      removed=$((removed + 1))
    fi
  done
  if [ "$removed" -eq 0 ]; then
    printf 'AutomateSTIG is already uninstalled from %s.\n' "$INSTALL_DIR"
  else
    printf 'Uninstalled AutomateSTIG from %s.\n' "$INSTALL_DIR"
  fi
  printf 'Assessment data was preserved in %s.\n' "${AUTOMATESTIG_DATA_DIR:-${HOME:-}/.automatestig}"
  printf 'Remove that data only after following your evidence-retention policy.\n'
  exit 0
fi

SYSTEM="$(uname -s 2>/dev/null || true)"
case "$SYSTEM" in
  Linux) TARGET_OS="unknown-linux-gnu"; COSIGN_OS="linux" ;;
  Darwin) TARGET_OS="apple-darwin"; COSIGN_OS="darwin" ;;
  *)
    err "unsupported operating system: ${SYSTEM:-unknown}; AutomateSTIG release binaries are available only for macOS and Linux"
    ;;
esac

ARCH="$(uname -m 2>/dev/null || true)"
case "$ARCH" in
  x86_64 | amd64)
    TARGET_ARCH="x86_64"
    COSIGN_ARCH="amd64"
    ;;
  arm64 | aarch64)
    TARGET_ARCH="aarch64"
    COSIGN_ARCH="arm64"
    ;;
  *) err "unsupported architecture: ${ARCH:-unknown}; supported CPUs are x86_64 and arm64" ;;
esac
TARGET="$TARGET_ARCH-$TARGET_OS"

need_cmd awk
need_cmd curl
need_cmd grep
need_cmd mktemp
need_cmd tar
need_cmd tr
need_cmd wc

[ -n "$TAG" ] || err "could not determine a release tag"
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

rollback_install() {
  [ "$TRANSACTION_ACTIVE" -eq 1 ] || return 0
  printf 'Rolling back incomplete AutomateSTIG installation...\n' >&2
  rollback_status=0
  [ "$INSTALLED_CLI" -eq 0 ] || rm -f "$INSTALL_DIR/automatestig" || rollback_status=1
  [ "$INSTALLED_GUI" -eq 0 ] || rm -f "$INSTALL_DIR/automatestig-gui" || rollback_status=1
  [ "$INSTALLED_BACKUP_TOOL" -eq 0 ] || rm -f "$INSTALL_DIR/automatestig-backup-restore" || rollback_status=1
  if [ "$MOVED_CLI" -eq 1 ] && path_exists "$INSTALL_TXN_DIR/backup/automatestig"; then
    mv "$INSTALL_TXN_DIR/backup/automatestig" "$INSTALL_DIR/automatestig" || rollback_status=1
  fi
  if [ "$MOVED_GUI" -eq 1 ] && path_exists "$INSTALL_TXN_DIR/backup/automatestig-gui"; then
    mv "$INSTALL_TXN_DIR/backup/automatestig-gui" "$INSTALL_DIR/automatestig-gui" || rollback_status=1
  fi
  if [ "$MOVED_BACKUP_TOOL" -eq 1 ] && path_exists "$INSTALL_TXN_DIR/backup/automatestig-backup-restore"; then
    mv "$INSTALL_TXN_DIR/backup/automatestig-backup-restore" "$INSTALL_DIR/automatestig-backup-restore" || rollback_status=1
  fi
  [ "$rollback_status" -ne 0 ] || TRANSACTION_ACTIVE=0
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
    printf 'error: rollback failed; prior binaries are preserved in %s/backup\n' "$INSTALL_TXN_DIR" >&2
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

# Fetch the authentication material first. Older releases predate the scanner
# release contract; fail clearly and without downloading or changing programs.
printf 'Checking signed release %s for %s...\n' "$TAG" "$TARGET"
if ! curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --connect-timeout 15 \
  -o "$BUNDLE_PATH" "$DOWNLOAD_BASE/$BUNDLE_NAME"; then
  err "AutomateSTIG $TAG is not an installable scanner release: $BUNDLE_NAME is not published; no files were changed"
fi

printf 'Downloading AutomateSTIG %s...\n' "$TAG"
curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --connect-timeout 15 \
  -o "$ARCHIVE_PATH" "$DOWNLOAD_BASE/$ARCHIVE_NAME" || err "failed to download $ARCHIVE_NAME"
curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --connect-timeout 15 \
  -o "$CHECKSUM_PATH" "$DOWNLOAD_BASE/$CHECKSUM_NAME" || err "failed to download $CHECKSUM_NAME"

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
ACTUAL_HASH="$(sha256_file "$ARCHIVE_PATH")"
[ "$(printf '%s' "$EXPECTED_HASH" | tr 'A-F' 'a-f')" = "$(printf '%s' "$ACTUAL_HASH" | tr 'A-F' 'a-f')" ] ||
  err "checksum verification failed for $ARCHIVE_NAME"

if command -v cosign >/dev/null 2>&1; then
  COSIGN="$(command -v cosign)"
else
  COSIGN_NAME="cosign-$COSIGN_OS-$COSIGN_ARCH"
  case "$COSIGN_NAME" in
    cosign-darwin-amd64) COSIGN_HASH="4c3e7af8372d3ca3296e62fa56f23fcbb5721cc6ac1827900d398f110d7cd280" ;;
    cosign-darwin-arm64) COSIGN_HASH="5fadd012ae6381a6a29ff86a7d39aa873878852f1073fc90b15995961ecfb084" ;;
    cosign-linux-amd64) COSIGN_HASH="c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74" ;;
    cosign-linux-arm64) COSIGN_HASH="bedac92e8c3729864e13d4a17048007cfafa79d5deca993a43a90ffe018ef2b8" ;;
    *) err "no verified Cosign bootstrap is available for $SYSTEM $ARCH" ;;
  esac
  COSIGN="$TMP_DIR/cosign"
  printf 'Cosign is not installed; downloading the pinned verifier %s...\n' "$COSIGN_VERSION"
  curl --proto '=https' --proto-redir '=https' -fsSL --retry 3 --connect-timeout 15 \
    -o "$COSIGN" "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/$COSIGN_NAME" ||
    err "failed to download the pinned Cosign verifier"
  [ "$(sha256_file "$COSIGN")" = "$COSIGN_HASH" ] || err "pinned Cosign checksum verification failed"
  chmod 0700 "$COSIGN" || err "failed to prepare the temporary Cosign verifier"
fi

printf 'Verifying tagged-workflow Sigstore identity...\n'
IDENTITY="https://github.com/$REPO/.github/workflows/ci.yml@refs/tags/$TAG"
COSIGN_EXPERIMENTAL=1 "$COSIGN" verify-blob \
  --bundle "$BUNDLE_PATH" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARCHIVE_PATH" >/dev/null || err "Sigstore verification failed for $ARCHIVE_NAME"

printf 'Validating the closed release archive...\n'
EXPECTED_MEMBERS='automatestig
automatestig-gui
automatestig-backup-restore
README.md
LICENSE
quickstart.md
installation.md'
ARCHIVE_MEMBERS="$(tar -tzf "$ARCHIVE_PATH")" || err "could not inspect $ARCHIVE_NAME"
SORTED_EXPECTED="$(printf '%s\n' "$EXPECTED_MEMBERS" | LC_ALL=C sort)"
SORTED_ACTUAL="$(printf '%s\n' "$ARCHIVE_MEMBERS" | LC_ALL=C sort)"
[ "$SORTED_ACTUAL" = "$SORTED_EXPECTED" ] || err "unsafe or unexpected members in $ARCHIVE_NAME"
[ "$(printf '%s\n' "$ARCHIVE_MEMBERS" | wc -l | tr -d ' ')" -eq 7 ] ||
  err "release archive must contain each expected member exactly once"
tar -tvzf "$ARCHIVE_PATH" | awk '
  substr($1, 1, 1) != "-" { exit 1 }
  END { if (NR != 7) exit 1 }
' || err "release archive members must be exactly seven regular files"

if path_exists "$INSTALL_DIR"; then
  [ -d "$INSTALL_DIR" ] && [ ! -L "$INSTALL_DIR" ] || err "install directory must be a real directory: $INSTALL_DIR"
else
  mkdir -p "$INSTALL_DIR" || err "failed to create install directory: $INSTALL_DIR"
fi
[ -w "$INSTALL_DIR" ] || err "install directory is not writable: $INSTALL_DIR"

INSTALL_TXN_DIR="$(mktemp -d "$INSTALL_DIR/.automatestig-install.XXXXXX")" ||
  err "failed to create install transaction in $INSTALL_DIR"
mkdir -p "$INSTALL_TXN_DIR/stage" "$INSTALL_TXN_DIR/backup" || err "failed to prepare install transaction"

# Stream only the three expected programs into the private transaction. This
# avoids extracting documentation or allowing an archive path to choose an
# output location. The exact member listing above rejects duplicates and links;
# the file-size limit prevents an authenticated but malformed archive from
# exhausting the destination before the post-extraction bounds are checked.
TOTAL_PROGRAM_BYTES=0
for program in automatestig automatestig-gui automatestig-backup-restore; do
  (ulimit -f "$MAX_PROGRAM_BLOCKS" &&
    tar -xOzf "$ARCHIVE_PATH" "$program" >"$INSTALL_TXN_DIR/stage/$program") ||
    err "failed to stage $program"
  [ -s "$INSTALL_TXN_DIR/stage/$program" ] || err "$program is empty in $ARCHIVE_NAME"
  PROGRAM_BYTES="$(wc -c <"$INSTALL_TXN_DIR/stage/$program" | tr -d ' ')"
  case "$PROGRAM_BYTES" in *[!0-9]* | '') err "could not measure staged $program" ;; esac
  [ "$PROGRAM_BYTES" -le "$MAX_PROGRAM_BYTES" ] || err "$program exceeds the release size limit"
  TOTAL_PROGRAM_BYTES=$((TOTAL_PROGRAM_BYTES + PROGRAM_BYTES))
  [ "$TOTAL_PROGRAM_BYTES" -le "$MAX_TOTAL_PROGRAM_BYTES" ] ||
    err "release programs exceed the total size limit"
  chmod 0755 "$INSTALL_TXN_DIR/stage/$program" || err "failed to make $program executable"
done

# Probe the exact authenticated CLI before replacing an existing installation.
# This catches incompatible GNU libc/dynamic-loader builds on a Linux host
# without guessing a distribution or glibc floor. The release's native CI
# execution remains the authoritative supported-platform qualification.
if ! "$INSTALL_TXN_DIR/stage/automatestig" --version >/dev/null 2>&1; then
  err "the authenticated $TARGET release cannot run on this host; no installed files were changed"
fi

TRANSACTION_ACTIVE=1
if path_exists "$INSTALL_DIR/automatestig"; then
  MOVED_CLI=1
  mv "$INSTALL_DIR/automatestig" "$INSTALL_TXN_DIR/backup/automatestig" || err "failed to preserve existing automatestig"
fi
if path_exists "$INSTALL_DIR/automatestig-gui"; then
  MOVED_GUI=1
  mv "$INSTALL_DIR/automatestig-gui" "$INSTALL_TXN_DIR/backup/automatestig-gui" || err "failed to preserve existing automatestig-gui"
fi
if path_exists "$INSTALL_DIR/automatestig-backup-restore"; then
  MOVED_BACKUP_TOOL=1
  mv "$INSTALL_DIR/automatestig-backup-restore" "$INSTALL_TXN_DIR/backup/automatestig-backup-restore" || err "failed to preserve existing automatestig-backup-restore"
fi
INSTALLED_CLI=1
mv "$INSTALL_TXN_DIR/stage/automatestig" "$INSTALL_DIR/automatestig" || err "failed to publish automatestig"
INSTALLED_GUI=1
mv "$INSTALL_TXN_DIR/stage/automatestig-gui" "$INSTALL_DIR/automatestig-gui" || err "failed to publish automatestig-gui"
INSTALLED_BACKUP_TOOL=1
mv "$INSTALL_TXN_DIR/stage/automatestig-backup-restore" "$INSTALL_DIR/automatestig-backup-restore" || err "failed to publish automatestig-backup-restore"
TRANSACTION_ACTIVE=0
rm -rf "$INSTALL_TXN_DIR"
INSTALL_TXN_DIR=

printf '\nInstalled AutomateSTIG %s for %s in %s.\n' "$TAG" "$TARGET" "$INSTALL_DIR"
printf 'CLI: %s/automatestig\n' "$INSTALL_DIR"
printf 'Repair: run this verified installer again. Upgrade: download the installer from the new verified release.\n'
printf 'Uninstall: run this installer with --uninstall (assessment data is retained).\n'
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
  :
else
  printf 'Optional recovery utility note: automatestig-backup-restore requires Python 3.10 or newer.\n'
fi

if [ "$NO_LAUNCH" -eq 0 ]; then
  printf 'Starting AutomateSTIG; your browser should open.\n'
  printf 'If it does not, run: %s/automatestig-gui\n' "$INSTALL_DIR"
  if command -v nohup >/dev/null 2>&1; then
    nohup "$INSTALL_DIR/automatestig-gui" </dev/null >/dev/null 2>&1 &
  else
    "$INSTALL_DIR/automatestig-gui" </dev/null >/dev/null 2>&1 &
  fi
else
  printf 'Launch when ready: %s/automatestig-gui\n' "$INSTALL_DIR"
fi
