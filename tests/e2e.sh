#!/bin/bash
# End-to-end test on a real disposable host with systemd and Docker.
# It installs RustDesk into /opt/rustdesk, exercises every command and removes
# everything at the end. Never run it on a production server.
#
#   RUSTDESK_E2E=1 bash tests/e2e.sh

set -euo pipefail

[ "${RUSTDESK_E2E:-}" = 1 ] || { echo "set RUSTDESK_E2E=1 to confirm this is a test host" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }
[ ! -e /opt/rustdesk ] || { echo "/opt/rustdesk already exists; refusing to touch it" >&2; exit 2; }

REPO=$(cd "$(dirname "$0")/.." && pwd)
CTL=/usr/local/sbin/rustdesk-ctl
OLD_IMAGE="rustdesk/rustdesk-server@sha256:10818ec05b179039c6660f4d8e74b303f0db2858bbad2b18e24992ea22d54cd6" # 1.1.15
STEP=""

step() { STEP="$*"; printf '\n=== %s\n' "$STEP"; }
fail() { printf 'FAIL [%s]: %s\n' "$STEP" "$*" >&2; exit 1; }
expect() {
    local out
    out=$("$@" 2>&1) || { printf '%s\n' "$out" >&2; fail "expected success: $*"; }
}
refuse() { if "$@" >/dev/null 2>&1; then fail "expected failure: $*"; fi; }
# Not `rustdesk-ctl version | grep -q`: grep exits early and pipefail turns
# the writer's SIGPIPE into a failure.
version_has() { local out; out=$("$CTL" version); grep -q "$1" <<< "$out"; }
started() { docker inspect -f '{{.State.StartedAt}}' hbbs hbbr; }
pin_old_image() {
    printf 'RUSTDESK_IMAGE=%s\n' "$OLD_IMAGE" > /opt/rustdesk/.env
    chmod 600 /opt/rustdesk/.env
    systemctl restart rustdesk-compose.service
    version_has 'hbbs 1.1.15' || fail "1.1.15 is not running"
}
since() { date '+%F %T'; }
cleanup() {
    rm -f /opt/rustdesk/docker-compose.override.yml 2>/dev/null || true
    [ -x "$CTL" ] && "$CTL" uninstall --purge --yes >/dev/null 2>&1 || true
}
on_exit() {
    local status=$?
    [ "$status" -eq 0 ] || { echo "e2e failed; cleaning up" >&2; cleanup; }
}
trap on_exit EXIT

step "install"
"$REPO/rustdesk-ctl" install
expect "$CTL" status
KEY1=$("$CTL" key show)
[ "$(stat -c %a /opt/rustdesk/data)" = 700 ] || fail "data directory is not 700"
[ "$(stat -c %a /opt/rustdesk/data/id_ed25519)" = 600 ] || fail "private key is not 600"
for unit in rustdesk-compose.service rustdesk-update.timer rustdesk-watchdog.timer; do
    systemctl is-enabled --quiet "$unit" || fail "$unit is not enabled"
done
[ -z "$(ss -Hltn 'sport = :21114')" ] || fail "something listens on 21114"
refuse runuser -u nobody -- cat /opt/rustdesk/data/id_ed25519
refuse runuser -u nobody -- "$CTL" status

step "version"
"$CTL" version
version_has 'Update:        not needed' || fail "version does not report the latest image"

step "reinstall keeps the key and the running containers"
BEFORE=$(started)
"$REPO/rustdesk-ctl" install >/dev/null
[ "$("$CTL" key show)" = "$KEY1" ] || fail "key changed"
[ "$(started)" = "$BEFORE" ] || fail "containers were recreated"

step "key rotation"
"$CTL" key rotate --yes
KEY2=$("$CTL" key show)
[ "$KEY2" != "$KEY1" ] || fail "key did not change"
expect "$CTL" status
systemctl restart rustdesk-compose.service
[ "$("$CTL" key show)" = "$KEY2" ] || fail "key changed after a restart"
ls /opt/rustdesk/key-backups/*/id_ed25519 >/dev/null || fail "no key backup"

step "update through the systemd unit"
pin_old_image
T=$(since)
systemctl start rustdesk-update.service || fail "update unit failed"
journalctl -u rustdesk-update.service --since "$T" -o cat | grep 'RustDesk updated'
version_has 'hbbs 1.1.16' || fail "not updated"
refuse docker image inspect "$OLD_IMAGE"
[ "$("$CTL" key show)" = "$KEY2" ] || fail "update changed the key"

step "failed update rolls back"
pin_old_image
printf 'services:\n  hbbr:\n    command: hbbr -k _ --e2e-bogus-flag\n' > /opt/rustdesk/docker-compose.override.yml
refuse systemctl start rustdesk-update.service
grep -q "$OLD_IMAGE" /opt/rustdesk/.env || fail ".env was not restored"
rm -f /opt/rustdesk/docker-compose.override.yml /opt/rustdesk/.env.backup.*
systemctl restart rustdesk-compose.service
expect "$CTL" status
expect systemctl start rustdesk-update.service
version_has 'hbbs 1.1.16' || fail "not updated after the rollback test"

step "watchdog restarts a stopped container"
rm -f /opt/rustdesk/.watchdog-restarts
T=$(since)
systemctl start rustdesk-watchdog.service
[ -z "$(journalctl -u rustdesk-watchdog.service --since "$T" -o cat)" ] || fail "a healthy watchdog run wrote to the journal"
docker stop hbbr >/dev/null
systemctl start rustdesk-watchdog.service || fail "watchdog run failed"
[ "$(docker inspect -f '{{.State.Status}}' hbbr)" = running ] || fail "hbbr was not restarted"
[ "$(wc -l < /opt/rustdesk/.watchdog-restarts)" -eq 1 ] || fail "restart not recorded"
journalctl -u rustdesk-watchdog.service --since "$T" -o cat | grep 'restarting rustdesk-compose'
expect "$CTL" status

step "watchdog gives up after 3 restarts an hour"
now=$(date +%s)
printf '%s\n' "$now" "$now" "$now" > /opt/rustdesk/.watchdog-restarts
docker stop hbbr >/dev/null
refuse systemctl start rustdesk-watchdog.service
[ "$(docker inspect -f '{{.State.Status}}' hbbr)" = exited ] || fail "watchdog restarted beyond its limit"
rm -f /opt/rustdesk/.watchdog-restarts
systemctl reset-failed rustdesk-watchdog.service
systemctl start rustdesk-watchdog.service
[ "$(docker inspect -f '{{.State.Status}}' hbbr)" = running ] || fail "hbbr was not restarted"

step "watchdog leaves a deliberately stopped server alone"
systemctl stop rustdesk-compose.service
systemctl start rustdesk-watchdog.service
refuse docker inspect hbbs
systemctl start rustdesk-compose.service
rm -f /opt/rustdesk/.watchdog-restarts
expect "$CTL" status

step "update and key rotation exclude each other"
pin_old_image
systemctl start --no-block rustdesk-update.service
sleep 3
refuse "$CTL" key rotate --yes
while [ "$(systemctl show -p ActiveState --value rustdesk-update.service)" = activating ]; do sleep 2; done
[ "$(systemctl show -p Result --value rustdesk-update.service)" = success ] || fail "update failed"
[ "$("$CTL" key show)" = "$KEY2" ] || fail "key changed during the update"

step "interrupted key rotation restores the key"
"$CTL" key rotate --yes > /dev/null 2>&1 &
pid=$!
sleep 1.5
kill -TERM "$pid"
wait "$pid" && fail "interrupted rotation reported success"
[ "$("$CTL" key show)" = "$KEY2" ] || fail "key was not restored"
expect "$CTL" status

step "timers"
systemctl list-timers --no-pager 'rustdesk-*'

step "uninstall keeps the key pair; reinstall reuses it"
"$CTL" uninstall --yes
[ -s /opt/rustdesk/data/id_ed25519 ] || fail "key pair was removed"
[ ! -e /etc/systemd/system/rustdesk-compose.service ] || fail "unit left behind"
[ ! -e "$CTL" ] || fail "rustdesk-ctl left behind"
refuse docker inspect hbbs
[ -z "$(docker image ls -q rustdesk/rustdesk-server)" ] || fail "image left behind"
"$REPO/rustdesk-ctl" install >/dev/null
[ "$("$CTL" key show)" = "$KEY2" ] || fail "reinstall did not reuse the key"
expect "$CTL" status

step "full removal (uninstall --purge) leaves nothing behind"
# Leftovers a server can collect: a drop-in, files of the debian-ubuntu-setup
# version, the lock it used and an image of another digest or tag.
mkdir -p /etc/systemd/system/rustdesk-compose.service.d
printf '[Service]\nEnvironment=E2E=1\n' > /etc/systemd/system/rustdesk-compose.service.d/override.conf
printf 'old\n' > /usr/local/sbin/rustdesk-safe-update.sh
: > /run/lock/rustdesk-update.lock
image_id=$(docker image ls -q rustdesk/rustdesk-server)
docker tag "${image_id%%$'\n'*}" rustdesk/rustdesk-server:e2e-leftover
systemctl daemon-reload
"$CTL" uninstall --purge --yes
# System locations only: home directories may hold unrelated copies of sources.
left=$(find /etc /opt /usr /var /srv /run -xdev \( -path "$REPO" -o -path /var/lib/docker \
        -o -path /var/lib/containerd -o -path /var/log/journal \) -prune -o -iname '*rustdesk*' -print 2>/dev/null)
[ -z "$left" ] || fail "files left behind: $left"
[ -z "$(systemctl list-unit-files --no-legend 'rustdesk*')" ] || fail "units left behind"
[ -z "$(systemctl list-units --all --no-legend 'rustdesk*')" ] || fail "loaded units left behind"
[ -z "$(docker ps -aq --filter name='^hbb[sr]$')" ] || fail "containers left behind"
[ -z "$(docker image ls -q rustdesk/rustdesk-server)" ] || fail "images left behind"
"$REPO/rustdesk-ctl" uninstall --purge --yes >/dev/null || fail "a second purge failed"

printf '\nAll end-to-end checks passed.\n'
