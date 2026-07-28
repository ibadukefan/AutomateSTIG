#!/bin/sh
# Thin wrapper around the shared, fail-closed Rust SSH collector. The required
# output path is written atomically with private permissions. A partial
# evidence v2 document is still written, then the command exits
# nonzero; never treat a nonzero run as a completed compliance collection.
#
# Usage:
#   AUTOMATESTIG_SSH_PASSWORD='...' ontap-collect.sh admin@filer evidence.json
#   AUTOMATESTIG_SSH_KEY=~/.ssh/id_ed25519 ontap-collect.sh admin@filer evidence.json
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 user@host output.json" >&2
    exit 2
fi

TARGET=$1
case "$TARGET" in
    *@*) USER=${TARGET%@*}; HOST=${TARGET#*@} ;;
    *) echo "target must be user@host" >&2; exit 2 ;;
esac
OUTPUT=$2
BIN=${AUTOMATESTIG_BIN:-automatestig}

if [ -n "${AUTOMATESTIG_SSH_KEY:-}" ]; then
    exec "$BIN" collect \
        --stig NetApp_ONTAP_DSC_9-x_STIG \
        --host "$HOST" --username "$USER" \
        --key "$AUTOMATESTIG_SSH_KEY" --output "$OUTPUT"
fi

exec "$BIN" collect \
    --stig NetApp_ONTAP_DSC_9-x_STIG \
    --host "$HOST" --username "$USER" --output "$OUTPUT"
