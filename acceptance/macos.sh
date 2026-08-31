#!/bin/sh
# Opt-in physical Secure Enclave and lifecycle acceptance. See acceptance/README.md.
set -eu
umask 077

usage() {
    echo "usage: $0 [--factorseal PATH] [--root ABSOLUTE_PATH] [--password-file PATH] [--event lock|switch|sleep] [--evidence ABSOLUTE_PATH] [--destroy-after]" >&2
    exit "${1:-2}"
}

factorseal=
root=
password_file=
evidence=
lifecycle_event=lock
destroy_after=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --factorseal) factorseal=${2:-}; shift 2 ;;
        --root) root=${2:-}; shift 2 ;;
        --password-file) password_file=${2:-}; shift 2 ;;
        --evidence) evidence=${2:-}; shift 2 ;;
        --event) lifecycle_event=${2:-}; shift 2 ;;
        --destroy-after) destroy_after=true; shift ;;
        --help|-h) usage 0 ;;
        *) usage ;;
    esac
done

script_dir=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
if [ -z "$factorseal" ] && [ -x "$script_dir/Factorseal.app/Contents/MacOS/factorseal" ]; then
    factorseal="$script_dir/Factorseal.app/Contents/MacOS/factorseal"
elif [ -z "$factorseal" ] && [ -x /Applications/Factorseal.app/Contents/MacOS/factorseal ]; then
    factorseal=/Applications/Factorseal.app/Contents/MacOS/factorseal
elif [ -z "$factorseal" ] && command -v factorseal >/dev/null 2>&1; then
    factorseal=$(command -v factorseal)
fi
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
[ -n "$root" ] || root="$HOME/Library/Application Support/Factorseal-acceptance-$run_id"
[ -n "$evidence" ] || evidence="$(pwd -P)/factorseal-macos-$lifecycle_event-$run_id.acceptance.txt"

[ -n "$factorseal" ] && [ -x "$factorseal" ] || {
    echo "Factorseal.app was not found beside the runner, in /Applications, or on PATH" >&2
    usage
}
[ "${root#/}" != "$root" ] || usage
[ ! -e "$root" ] || { echo "acceptance root already exists: $root" >&2; exit 2; }
[ -z "$password_file" ] || [ -f "$password_file" ] || usage
case $lifecycle_event in lock|switch|sleep) ;; *) usage ;; esac

case $factorseal in
    */Contents/MacOS/*) app_bundle=${factorseal%/Contents/MacOS/*} ;;
    *)
        echo "macOS acceptance requires Factorseal inside its signed .app bundle" >&2
        exit 2
        ;;
esac
if ! /usr/bin/codesign --verify --strict "$app_bundle" 2>/dev/null; then
    echo "Factorseal.app is unsigned or has an invalid code signature." >&2
    echo "The Data Protection Keychain requires a provisioned macOS app; unsigned CI artifacts cannot pass this acceptance test." >&2
    exit 2
fi
entitlements=$(/usr/bin/codesign -d --entitlements - --xml "$factorseal" 2>/dev/null) || {
    echo "could not read the Factorseal code-signing entitlements" >&2
    exit 2
}
application_identifier=$(printf '%s' "$entitlements" \
    | /usr/bin/plutil -extract 'com\.apple\.application-identifier' raw -o - - 2>/dev/null) || {
    echo "Factorseal.app lacks com.apple.application-identifier." >&2
    echo "Sign it with a provisioning profile that authorizes Data Protection Keychain access; unsigned CI artifacts cannot pass this acceptance test." >&2
    exit 2
}
[ -n "$application_identifier" ] || { echo "Factorseal.app has an empty application identifier" >&2; exit 2; }
[ -f "$app_bundle/Contents/embedded.provisionprofile" ] || {
    echo "Factorseal.app lacks Contents/embedded.provisionprofile, which must authorize its Data Protection Keychain entitlement." >&2
    exit 2
}
profile=$(/usr/bin/security cms -D -i "$app_bundle/Contents/embedded.provisionprofile" 2>/dev/null) || {
    echo "Factorseal.app contains an invalid embedded provisioning profile" >&2
    exit 2
}
profile_application_identifier=$(printf '%s' "$profile" \
    | /usr/bin/plutil -extract 'Entitlements.com\.apple\.application-identifier' raw -o - - 2>/dev/null) || {
    echo "Factorseal.app's provisioning profile does not authorize an application identifier" >&2
    exit 2
}
case $profile_application_identifier in
    *'*')
        profile_application_prefix=${profile_application_identifier%\*}
        case $application_identifier in
            "$profile_application_prefix"*) ;;
            *)
                echo "Factorseal.app's provisioning profile does not authorize $application_identifier" >&2
                exit 2
                ;;
        esac
        ;;
    "$application_identifier") ;;
    *)
        echo "Factorseal.app's provisioning profile does not authorize $application_identifier" >&2
        exit 2
        ;;
esac

hardware_summary=$(/usr/sbin/system_profiler SPHardwareDataType 2>/dev/null \
    | awk -F': ' '/Model Name|Model Identifier|Chip|Processor Name/ { printf "%s%s", separator, $2; separator="; " }')
[ -n "$hardware_summary" ] || { echo "could not identify physical Mac hardware" >&2; exit 2; }
case $(printf '%s' "$hardware_summary" | tr '[:upper:]' '[:lower:]') in
    *virtual*|*vmware*|*parallels*|*qemu*|*kvm*|*xen*)
        echo "physical acceptance refuses virtualized hardware: $hardware_summary" >&2
        exit 2
        ;;
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

echo "Factorseal physical macOS acceptance ($lifecycle_event)"
echo "  Test vault: $root"
echo "  Evidence:   $evidence"
echo "Native verification prompts will appear during creation, unseal, recovery, and cleanup."
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
record platform macos
record started_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
record factorseal_filename "$(basename "$factorseal")"
record factorseal_sha256 "$(shasum -a 256 "$factorseal" | awk '{print $1}')"
record factorseal_version "$("$factorseal" --version)"
record factorseal_application_identifier "$application_identifier"
record os_summary "macOS $(sw_vers -productVersion); $(uname -m)"
record expected_backend secure-enclave
record physical_host_check pass
record hardware_summary "$hardware_summary"
record lifecycle_event "$lifecycle_event"

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
observed_backend=$(status | sed -n 's/.*"hardware_backend": "\([^"]*\)".*/\1/p')
[ "$observed_backend" = secure-enclave ]
record observed_backend "$observed_backend"
record test.create pass

# Sealing invariants that a create-once flow cannot observe: that re-sealing
# under a label leaves an earlier envelope openable, that another label cannot
# open it, and that delete is label-scoped. Reserved scratch keychain items
# only. The biometric half asks for verification several times.
echo "The hardware self-test asks for verification several times."
"$factorseal" --root "$root" hardware-self-test --biometric
record test.hardware_self_test pass

"$factorseal" --root "$root" --password-file "$password_file" \
    agent --idle-seconds 3600 --maximum-seconds 3600 >"$root/acceptance-unseal.log" 2>&1 &
vault_pid=$!
wait_for unsealed
printf 'Did you see native verification for both creation and initial unseal? [y/N] '
read -r prompts_observed
case $prompts_observed in y|Y|yes|YES|Yes) ;; *) echo "both native verification prompts must be observed" >&2; exit 1 ;; esac
record native_prompt_create_observed pass
record native_prompt_unseal_observed pass
record native_prompt_observed pass
record test.initial_unseal pass
printf '%s' 'hardware-lifecycle-acceptance' | "$factorseal" --root "$root" set acceptance --field value
[ "$("$factorseal" --root "$root" get acceptance --field value)" = "hardware-lifecycle-acceptance" ]
record test.ipc_round_trip pass

echo "Trigger the requested macOS lifecycle event now: $lifecycle_event."
echo "After returning to this session, press Enter."
printf 'Press Enter after the lifecycle event: '
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
