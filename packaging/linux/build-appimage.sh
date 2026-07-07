#!/bin/sh
# AppImage is produced for x86_64 only (appimagetool runtime); arm64 Linux
# users use the .tar.gz archive.
set -e

if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <binaries-dir> <version> <arch> <outdir>" >&2
  exit 2
fi

BINARIES_DIR="$1"
VERSION="$2"
ARCH="$3"
OUTDIR="$4"

if [ "$ARCH" != "x86_64" ]; then
  echo "AppImage packaging is only supported for x86_64; use the .tar.gz archive for $ARCH." >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APPDIR="$OUTDIR/AutomateSTIG.AppDir"
APPIMAGE="$OUTDIR/AutomateSTIG-$VERSION-linux-x86_64.AppImage"
APPIMAGETOOL="$OUTDIR/appimagetool-x86_64.AppImage"

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$OUTDIR"

cp "$BINARIES_DIR/automatestig" "$APPDIR/usr/bin/automatestig"
cp "$BINARIES_DIR/automatestig-gui" "$APPDIR/usr/bin/automatestig-gui"
chmod +x "$APPDIR/usr/bin/automatestig" "$APPDIR/usr/bin/automatestig-gui"

cp "$ROOT/packaging/linux/automatestig.desktop" "$APPDIR/automatestig.desktop"
cp "$ROOT/packaging/icon/automatestig-256.png" "$APPDIR/automatestig.png"

cat > "$APPDIR/AppRun" <<'APPRUN'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/automatestig-gui" "$@"
APPRUN
chmod +x "$APPDIR/AppRun"

curl -fsSL -o "$APPIMAGETOOL" "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
chmod +x "$APPIMAGETOOL"

rm -f "$APPIMAGE"
if [ -e /dev/fuse ]; then
  ARCH=x86_64 "$APPIMAGETOOL" "$APPDIR" "$APPIMAGE"
else
  ARCH=x86_64 "$APPIMAGETOOL" --appimage-extract-and-run "$APPDIR" "$APPIMAGE"
fi
