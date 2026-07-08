#!/bin/sh
# AutomateSTIG NetApp ONTAP evidence collector.
#
# Runs read-only ONTAP CLI show commands over SSH and emits an evidence
# transcript on stdout in the format `automatestig evaluate --evidence`
# consumes. Nothing is installed on the filer and nothing is modified;
# the two advanced-privilege commands are read-only "show" commands.
#
# Usage:
#   scripts/collectors/ontap-collect.sh admin@filer > filer-evidence.txt
#   scripts/collectors/ontap-collect.sh admin@filer mycluster01 > filer-evidence.txt
#
# The optional second argument sets the hostname recorded in the transcript
# (defaults to the SSH target).
set -eu

TARGET="$1"
HOSTNAME="${2:-${TARGET#*@}}"

echo "### automatestig:hostname ${HOSTNAME}"

run() {
    # $1 = storage key (plain command), $2 = actual remote command line
    echo "### automatestig:command $1"
    ssh "$TARGET" "$2" 2>&1 || true
}

plain() {
    run "$1" "$1"
}

advanced() {
    run "$1" "set -privilege advanced -confirmations off; $1"
}

plain "security session limit show -interface cli"
plain "system timeout show"
plain "cluster log-forwarding show"
plain "security login show -role admin -authentication-method password"
plain "security login role config show -role admin -instance"
plain "security login banner show"
plain "vserver audit show -fields audit-guarantee"
plain "cluster time-service ntp server show"
plain "cluster date show"
plain "security login show -authentication-method domain"
plain "security login show -role admin -authentication-method domain"
plain "options -option-name snmp*"
plain "security snmpusers -authmethod usm"
plain "security login role config show -role admin -fields passwd-minlength"
plain "security login role config show -role admin -fields passwd-min-uppercase-chars"
plain "security login role config show -role admin -fields passwd-min-lowercase-chars"
plain "security login role config show -role admin -fields passwd-alphanum"
plain "security login role config show -role admin -fields passwd-min-special-chars"
advanced "system configuration backup show"
advanced "security config show"
