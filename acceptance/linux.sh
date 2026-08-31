#!/bin/sh
# Opt-in physical TPM and lifecycle acceptance. See acceptance/README.md.
set -eu
umask 077

usage() {
    echo "usage: $0 [--factorseal PATH] [--root ABSOLUTE_PATH] [--password-file PATH] [--evidence ABSOLUTE_PATH] [--destroy-after]" >&2
    exit "${1:-2}"
}

factorseal=
root=
password_file=
evidence=
destroy_after=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --factorseal) factorseal=${2:-}; shift 2 ;;
        --root) root=${2:-}; shift 2 ;;
        --password-file) password_file=${2:-}; shift 2 ;;
        --evidence) evidence=${2:-}; shift 2 ;;
        --destroy-after) destroy_after=true; shift ;;
        --help|-h) usage 0 ;;
        *) usage ;;
    esac
done

script_dir=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
if [ -z "$factorseal" ] && [ -x "$script_dir/bin/factorseal" ]; then
    factorseal="$script_dir/bin/factorseal"
elif [ -z "$factorseal" ] && command -v factorseal >/dev/null 2>&1; then
    factorseal=$(command -v factorseal)
fi
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
[ -n "$root" ] || root="${XDG_DATA_HOME:-$HOME/.local/share}/factorseal-acceptance-$run_id"
[ -n "$evidence" ] || evidence="$(pwd -P)/factorseal-linux-$run_id.acceptance.txt"

[ -n "$factorseal" ] && [ -x "$factorseal" ] || {
    echo "factorseal was not found beside the runner or on PATH" >&2
    usage
}
[ "${root#/}" != "$root" ] || usage
[ ! -e "$root" ] || { echo "acceptance root already exists: $root" >&2; exit 2; }
[ -z "$password_file" ] || [ -f "$password_file" ] || usage
command -v systemd-detect-virt >/dev/null 2>&1 || { echo "systemd-detect-virt is required" >&2; exit 2; }
if systemd-detect-virt --quiet; then
    echo "physical acceptance refuses virtualized hosts (detected: $(systemd-detect-virt))" >&2
    exit 2
fi
[ -c /dev/tpmrm0 ] || { echo "a physical TPM resource manager (/dev/tpmrm0) is required" >&2; exit 2; }

if [ -z "${XDG_SESSION_ID:-}" ]; then
    XDG_SESSION_ID=$(loginctl show-user "$(id -u)" --property=Display --value 2>/dev/null || true)
    export XDG_SESSION_ID
fi
[ -n "${XDG_SESSION_ID:-}" ] || {
    echo "could not identify the active desktop session; run this from its terminal" >&2
    exit 2
}
case $(loginctl show-session "$XDG_SESSION_ID" --property=Remote --value 2>/dev/null || true) in
    yes) echo "run physical acceptance from the local desktop, not through SSH" >&2; exit 2 ;;
esac

[ "${evidence#/}" != "$evidence" ] || { echo "evidence path must be absolute" >&2; exit 2; }
case $evidence in
    *.txt) evidence_partial="${evidence%.txt}.partial.txt" ;;
    *) evidence_partial="${evidence}.partial" ;;
esac
[ ! -e "$evidence" ] && [ ! -e "$evidence_partial" ] || {
    echo "evidence path already exists: $evidence or $evidence_partial" >&2
    exit 2
}
[ -d "$(dirname "$evidence")" ] || { echo "evidence parent directory does not exist" >&2; exit 2; }

vault_pid=
acceptance_passed=false
generated_password_file=
cleanup() {
    if [ -n "$vault_pid" ] && kill -0 "$vault_pid" 2>/dev/null; then
        kill -TERM "$vault_pid" 2>/dev/null || true
        wait "$vault_pid" || true
    fi
    if [ -n "$generated_password_file" ]; then
        if [ "$acceptance_passed" = true ] || [ ! -e "$root" ]; then
            rm -f "$generated_password_file"
        else
            echo "Test did not finish; the temporary factor was retained for cleanup: $generated_password_file" >&2
        fi
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -z "$password_file" ]; then
    password_file=$(mktemp "${TMPDIR:-/tmp}/factorseal-acceptance-password.XXXXXX")
    generated_password_file=$password_file
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$password_file"
    destroy_after=true
fi

echo "Factorseal physical Linux acceptance"
echo "  Test vault: $root"
echo "  Evidence:   $evidence"
if [ -n "$generated_password_file" ]; then
    echo "The guided run uses a generated test-only factor and removes the test vault after success."
else
    echo "The test vault is kept unless --destroy-after is supplied."
fi

record() {
    record_key=$1
    record_value=$(printf '%s' "$2" | tr '\r\n\t=' '    ')
    printf '%s=%s\n' "$record_key" "$record_value" >>"$evidence_partial"
}
record schema factorseal-physical-acceptance-v1
record platform linux
record started_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record factorseal_filename "$(basename "$factorseal")"
record factorseal_sha256 "$(sha256sum "$factorseal" | awk '{print $1}')"
record factorseal_version "$("$factorseal" --version)"
record os_summary "$(uname -srmo)"
record expected_backend tpm
record physical_host_check pass
record hardware_summary "$(cat /sys/class/tpm/tpm0/device/description 2>/dev/null || printf 'TPM 2.0 at /dev/tpmrm0')"
record native_prompt_observed not-applicable
record lifecycle_event logind-lock

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

"$factorseal" --root "$root" --password-file "$password_file" init
observed_backend=$(status | sed -n 's/.*"hardware_backend": "\([^"]*\)".*/\1/p')
[ "$observed_backend" = tpm ]
record observed_backend "$observed_backend"
record test.create pass

# Sealing invariants that a create-once flow cannot observe: that re-sealing
# under a label leaves an earlier envelope openable, that another label cannot
# open it, and that delete is label-scoped. Reserved scratch state only.
"$factorseal" --root "$root" hardware-self-test
record test.hardware_self_test pass

"$factorseal" --root "$root" --password-file "$password_file" \
    agent --idle-seconds 3600 --maximum-seconds 3600 >"$root/acceptance-unseal.log" 2>&1 &
vault_pid=$!
wait_for unsealed
record test.initial_unseal pass
printf '%s' 'hardware-lifecycle-acceptance' | "$factorseal" --root "$root" set acceptance --field value
[ "$("$factorseal" --root "$root" get acceptance --field value)" = "hardware-lifecycle-acceptance" ]
record test.ipc_round_trip pass

echo "Lock this session now (for example: loginctl lock-session \"$XDG_SESSION_ID\")."
echo "After unlocking again, return here and press Enter."
printf 'Press Enter after the lock/unlock: '
read -r _
wait_for_vault_exit
wait_for sealed
record test.lifecycle_seal pass
if "$factorseal" --root "$root" get acceptance --field value >/dev/null 2>&1; then
    echo "sealed vault returned a secret" >&2
    exit 1
fi
record test.sealed_read_denied pass

"$factorseal" --root "$root" --password-file "$password_file" \
    agent --idle-seconds 3600 --maximum-seconds 3600 >"$root/acceptance-reunseal.log" 2>&1 &
vault_pid=$!
wait_for unsealed
[ "$("$factorseal" --root "$root" get acceptance --field value)" = "hardware-lifecycle-acceptance" ]
record test.reunseal_recovery pass
"$factorseal" --root "$root" delete acceptance --field value
record test.delete pass
kill -TERM "$vault_pid"
wait "$vault_pid"
vault_pid=
wait_for sealed

if [ "$destroy_after" = true ]; then
    "$factorseal" --root "$root" --password-file "$password_file" destroy --yes-really-destroy
    record test.destroy pass
else
    record test.destroy not-run
fi
record completed_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mv "$evidence_partial" "$evidence"
acceptance_passed=true
echo "PASS — send this evidence file to the Factorseal maintainers: $evidence"
echo "Upload it to https://github.com/domenkozar/factorseal/issues/2"
