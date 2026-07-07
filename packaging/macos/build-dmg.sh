#!/bin/sh
# Build a distributable AutomateSTIG-<version>-<arch>.dmg from a built .app.
# Usage: build-dmg.sh <path-to-AutomateSTIG.app> <version> <arch> <output-dir>
set -e
APP="$1"; VERSION="${2:-0.0.0}"; ARCH="${3:-universal}"; OUTDIR="${4:-.}"
STAGE="$(mktemp -d)"
cp -R "$APP" "$STAGE/AutomateSTIG.app"
ln -s /Applications "$STAGE/Applications"
DMG="$OUTDIR/AutomateSTIG-$VERSION-macos-$ARCH.dmg"
rm -f "$DMG"
hdiutil create -volname "AutomateSTIG $VERSION" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"
echo "Built $DMG"
