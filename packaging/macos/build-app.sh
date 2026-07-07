#!/bin/sh
# Build AutomateSTIG.app from a built automatestig-gui binary.
# Usage: build-app.sh <path-to-automatestig-gui> <version> <output-dir>
set -e
BIN="$1"; VERSION="${2:-0.0.0}"; OUTDIR="${3:-.}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ICNS="$ROOT/packaging/icon/AutomateSTIG.icns"
APP="$OUTDIR/AutomateSTIG.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/automatestig-gui"
chmod +x "$APP/Contents/MacOS/automatestig-gui"
cp "$ICNS" "$APP/Contents/Resources/AutomateSTIG.icns"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>AutomateSTIG</string>
  <key>CFBundleDisplayName</key><string>AutomateSTIG</string>
  <key>CFBundleIdentifier</key><string>mil.disa.automatestig</string>
  <key>CFBundleExecutable</key><string>automatestig-gui</string>
  <key>CFBundleIconFile</key><string>AutomateSTIG</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
touch "$APP"
echo "Built $APP"
