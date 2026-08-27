#!/bin/sh
# Opt-in physical Secure Enclave and lifecycle acceptance. See acceptance/README.md.
set -eu

usage() {
    echo "usage: $0 --factorseal PATH --root ABSOLUTE_PATH --password-file PATH [--destroy-after]" >&2
    exit "${1:-2}"
}

factorseal=
root=
password_file=
destroy_after=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --factorseal) factorseal=${2:-}; shift 2 ;;
        --root) root=${2:-}; shift 2 ;;
        --password-file) password_file=${2:-}; shift 2 ;;
        --destroy-after) destroy_after=true; shift ;;
        --help|-h) usage 0 ;;
        *) usage ;;
    esac
done

[ -n "$factorseal" ] && [ -x "$factorseal" ] || usage
[ -n "$root" ] && [ "${root#/}" != "$root" ] || usage
[ ! -e "$root" ] || { echo "acceptance root already exists: $root" >&2; exit 2; }
[ -n "$password_file" ] && [ -f "$password_file" ] || usage

vault_pid=
cleanup() {
    if [ -n "$vault_pid" ] && kill -0 "$vault_pid" 2>/dev/null; then
        kill -TERM "$vault_pid" 2>/dev/null || true
        wait "$vault_pid" || true
    fi
}
trap cleanup EXIT HUP INT TERM

status() { "$factorseal" --root "$root" status; }
wait_for() {
    expected=$1
    attempts=0
    while [ "$attempts" -lt 180 ]; do
        if status 2>/dev/null | grep -q "\"state\": \"$expected\""; then return 0; fi
        attempts=$((attempts + 1))
        sleep 1
    done
    echo "vault did not become $expected within three minutes" >&2
    return 1
}

wait_for_vault_exit() {
    attempts=0
    while kill -0 "$vault_pid" 2>/dev/null; do
        if [ "$attempts" -ge 180 ]; then
            echo "vault did not exit after the lifecycle event within three minutes" >&2
            return 1
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    wait "$vault_pid"
    vault_pid=
}

"$factorseal" --root "$root" --password-file "$password_file" init --unlock password,biometric
status | grep -q '"hardware_backend": "secure-enclave"'

"$factorseal" --root "$root" --password-file "$password_file" \
    unseal --idle-seconds 3600 --maximum-seconds 3600 >"$root/acceptance-unseal.log" 2>&1 &
vault_pid=$!
wait_for unsealed
printf '%s' 'hardware-lifecycle-acceptance' | "$factorseal" --root "$root" set acceptance --field value
[ "$("$factorseal" --root "$root" get acceptance --field value)" = "hardware-lifecycle-acceptance" ]

echo "Lock/switch away from this session or put the Mac to sleep now."
echo "The runner will fail if the real AppKit lifecycle notification does not seal the vault."
printf 'Press Enter after initiating the lifecycle event: '
read -r _
wait_for_vault_exit
wait_for sealed
if "$factorseal" --root "$root" get acceptance --field value >/dev/null 2>&1; then
    echo "sealed vault returned a secret" >&2
    exit 1
fi

"$factorseal" --root "$root" --password-file "$password_file" \
    unseal --idle-seconds 3600 --maximum-seconds 3600 >"$root/acceptance-reunseal.log" 2>&1 &
vault_pid=$!
wait_for unsealed
[ "$("$factorseal" --root "$root" get acceptance --field value)" = "hardware-lifecycle-acceptance" ]
"$factorseal" --root "$root" delete acceptance --field value
kill -TERM "$vault_pid"
wait "$vault_pid"
vault_pid=
wait_for sealed

if [ "$destroy_after" = true ]; then
    "$factorseal" --root "$root" --password-file "$password_file" destroy --yes-really-destroy
fi
echo "macOS native hardware/lifecycle acceptance passed."
