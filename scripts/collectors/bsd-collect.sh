#!/bin/sh
# Thin wrapper around the shared, fail-closed Rust SSH collector. The required
# output path is written atomically with private permissions. A partial
# evidence v2 document is still written, then the command exits
# nonzero; never treat a nonzero run as a completed compliance collection.
#
# Usage:
#   AUTOMATESTIG_SSH_PASSWORD='...' bsd-collect.sh admin@bsdhost evidence.json
#   AUTOMATESTIG_SSH_KEY=~/.ssh/id_ed25519 bsd-collect.sh admin@bsdhost evidence.json bsd01
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 user@host output.json [evidence-hostname]" >&2
    exit 2
fi

TARGET=$1
case "$TARGET" in
    *@*) USER=${TARGET%@*}; HOST=${TARGET#*@} ;;
    *) echo "target must be user@host" >&2; exit 2 ;;
esac
OUTPUT=$2
HOSTNAME=${3:-$HOST}
BIN=${AUTOMATESTIG_BIN:-automatestig}

if [ -n "${AUTOMATESTIG_SSH_KEY:-}" ]; then
    exec "$BIN" collect \
        --stig General_Purpose_Operating_System \
        --host "$HOST" --hostname "$HOSTNAME" --username "$USER" \
        --key "$AUTOMATESTIG_SSH_KEY" --output "$OUTPUT"
fi

exec "$BIN" collect \
    --stig General_Purpose_Operating_System \
    --host "$HOST" --hostname "$HOSTNAME" --username "$USER" --output "$OUTPUT"
