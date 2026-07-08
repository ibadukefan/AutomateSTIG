#!/bin/sh
# AutomateSTIG FreeBSD evidence collector.
#
# Runs read-only commands over SSH and emits an evidence transcript on
# stdout in the format `automatestig evaluate --evidence` consumes.
# Collects configuration text only — no password hashes or other secrets.
#
# Usage:
#   scripts/collectors/bsd-collect.sh admin@bsdhost > bsdhost-evidence.txt
#   scripts/collectors/bsd-collect.sh admin@bsdhost bsdhost01 > bsdhost-evidence.txt
set -eu

TARGET="$1"
HOSTNAME="${2:-${TARGET#*@}}"

echo "### automatestig:hostname ${HOSTNAME}"

run() {
    echo "### automatestig:command $1"
    ssh "$TARGET" "$1" 2>&1 || true
}

run "freebsd-version -k"
run "cat /etc/ssh/sshd_config"
run "cat /etc/motd.template /etc/motd"
run "cat /etc/login.conf"
run "cat /etc/pam.d/passwd"
run "cat /etc/security/audit_control"
run "service auditd onestatus"
run "cat /etc/ntp.conf"
run "cat /var/db/zoneinfo"
run "sysctl kern.elf64.aslr.enable"
run "cat /etc/rc.conf"
