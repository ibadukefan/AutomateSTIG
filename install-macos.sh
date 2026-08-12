#!/bin/sh
# Compatibility entry point. New installs should use the unified install.sh.
set -eu

err() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[ "$(uname -s 2>/dev/null || true)" = "Darwin" ] ||
  err "this installer is for macOS; use install.sh to detect the platform automatically"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || SCRIPT_DIR=
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/install.sh" ]; then
  exec sh "$SCRIPT_DIR/install.sh" "$@"
fi

err "install.sh was not found beside this compatibility wrapper; download install.sh from a verified GitHub Release and run it directly"
