#!/usr/bin/env bash
# Checks FactorSeal Desktop's approval popup on Windows from WSL2.
#
#   check.sh popup [--delay SECONDS] [--key KEY] [--observe SECONDS]
#       Send a WSL-relayed request and report whether the popup opened, whether
#       it reached the foreground or flashed its taskbar button, a screenshot,
#       and whether the vault holds the pending request with its WSL origin.
#       --delay waits before sending, so a focus scenario can be set up.
#   check.sh grant [--key KEY]
#       After approving in the popup, resend the request and check that it
#       succeeds without a new popup and that the grant is capped at 300 s.
#
# Needs Desktop running and unsealed, the native Windows build of the CLI,
# and the cross-compiled broker. Paths can be overridden with
# FACTORSEAL_WINDOWS_TREE (Windows copy of this repository, as a WSL path) and
# FACTORSEAL_WSL_BROKER.
set -euo pipefail

case ${1:-} in
    popup | grant) ;;
    *) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac

repo=$(cd "$(dirname "$0")/../.." && pwd)
here=$(cd "$(dirname "$0")" && pwd)

windows_profile=$(wslpath "$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')")
windows_tree=${FACTORSEAL_WINDOWS_TREE:-$windows_profile/Projects/factorseal}
cli="$windows_tree/target/release/factorseal.exe"
broker=${FACTORSEAL_WSL_BROKER:-$repo/target/x86_64-pc-windows-msvc/release/factorseal-wsl-broker.exe}
distro=${WSL_DISTRO_NAME:?not running inside WSL}
project=wsl-ui-check
profile=default
max_wsl_grant_seconds=300

die() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$cli" ] || die "no native CLI at $cli; build it on Windows (see docs/development.md)"
[ -x "$broker" ] || die "no broker at $broker; build it with:
  devenv shell -- cargo xwin build --release --target x86_64-pc-windows-msvc --bin factorseal-wsl-broker --features vault-client"

# The vault seals itself after a few idle minutes, so check before sending.
require_unsealed() {
    status=$("$cli" status </dev/null 2>&1) || die "factorseal status failed: $status"
    installation=$(sed -n 's/.*"installation_id": "\([^"]*\)".*/\1/p' <<<"$status")
    state=$(sed -n 's/.*"state": "\([^"]*\)".*/\1/p' <<<"$status")
    [ -n "$installation" ] || die "no installation_id in factorseal status"
    [ "$state" = unsealed ] || die "vault is $state; unlock it in Desktop first"
}
require_unsealed
pipe="\\\\.\\pipe\\factorseal-$installation"

send() { timeout 60 "$broker" "$pipe" "$distro" get "$project" "$profile" "$1" 2>&1 || true; }

# Prints the permission block for one request ID, or nothing.
permission() {
    "$cli" permissions list </dev/null 2>&1 | awk -v id="\"$1\"" '
        $1 == id { found = 1; print; next }
        found && /^"prm_/ { exit }
        found { print }'
}

command=${1:-}
shift || true
key="CHECK_$(date +%H%M%S)"
key_given=no
delay=0
observe=12
while [ $# -gt 0 ]; do
    case $1 in
        --key) key=$2; key_given=yes; shift 2 ;;
        --delay) delay=$2; shift 2 ;;
        --observe) observe=$2; shift 2 ;;
        *) die "unknown option $1" ;;
    esac
done

case $command in
popup)
    out=$(mktemp -d "${TMPDIR:-/tmp}/factorseal-popup-check.XXXXXX")
    win_out=$(wslpath -w "$out")
    # The observer runs on Windows; copy it next to its output so the
    # Windows side reads a local path.
    cp "$here/observe.ps1" "$out/observe.ps1"
    if [ "$delay" -gt 0 ]; then
        echo "Sending in $delay s; set up the focus scenario now."
        sleep "$delay"
        require_unsealed
    fi
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$win_out\\observe.ps1" \
        -OutDir "$win_out" -Seconds "$observe" >"$out/powershell.txt" 2>&1 &
    observer=$!
    # Windows PowerShell writes UTF-8 with a byte-order mark and CRLF endings.
    report() { sed '1s/^\xEF\xBB\xBF//' "$out/observer.txt" 2>/dev/null | tr -d '\r'; }
    value() { report | sed -n "s/^$1=//p" | tail -1; }
    for _ in $(seq 150); do
        [ -e "$out/ready" ] && break
        kill -0 "$observer" 2>/dev/null || break
        sleep 0.1
    done
    [ -n "$(value error)" ] && die "$(value error)"
    [ -e "$out/ready" ] || die "observer did not start; see $out/powershell.txt"

    echo "Sending request for $project/$profile/$key at $(date -u +%T) UTC"
    echo "Leave the popup alone until the result prints."
    reply=$(send "$key")
    wait "$observer" || true
    id=$(sed -n 's/.*approval required (id \(prm_[^)]*\)).*/\1/p' <<<"$reply")

    seen=$(value popup_seen)
    foreground=$(value popup_foreground)
    flashed=$(value popup_flashed)
    echo
    echo "broker:        ${reply//$'\n'/ | }"
    echo "popup seen:    $seen ($(value popup_title))"
    echo "foreground:    $foreground (foreground window: $(value foreground_process) '$(value foreground_title)')"
    echo "flashed:       $flashed ($(value flash_events) flash events in total)"
    echo "rect:          $(value popup_rect)"
    [ -n "$(value popup_screenshot)" ] && echo "screenshot:    $out/popup.png (what was on screen at the popup's position)"
    [ -n "$(value taskbar_screenshot)" ] && echo "taskbar:       $out/taskbar.png"

    failures=0
    if grep -q 'no vault agent is listening' <<<"$reply"; then
        die "the vault sealed before the request arrived; unlock it and run again"
    elif [ -z "$id" ]; then
        echo "vault:         no pending request (already granted, or the broker failed)"
        failures=$((failures + 1))
    elif grep -q 'approval not granted: Denied' <<<"$reply"; then
        echo "vault:         $id was denied in the popup during the run; not checked"
    else
        record=$(permission "$id")
        if grep -q 'pending' <<<"$record" && grep -q "relayed from WSL distro: \"$distro\"" <<<"$record"; then
            echo "vault:         $id pending, relayed from $distro"
        else
            echo "vault:         $id not pending with WSL origin:"; sed 's/^/  /' <<<"$record"
            failures=$((failures + 1))
        fi
    fi
    if [ "$seen" != True ]; then
        echo "FAIL: the popup never opened"; failures=$((failures + 1))
    elif [ "$foreground" != True ] && [ "$flashed" != True ]; then
        echo "FAIL: the popup is behind another app and did not flash"; failures=$((failures + 1))
    fi
    [ "$failures" -eq 0 ] && echo "PASS" || exit 1
    echo "Approve or deny it in the popup. After approving, run: $0 grant --key $key"
    ;;
grant)
    [ "$key_given" = yes ] || die "grant needs --key KEY from the popup run"
    reply=$(send "$key")
    grep -q 'approval required' <<<"$reply" && die "the request needed approval again: $reply"
    echo "broker:        ${reply//$'\n'/ | }"
    # The target line, right after each ID line, holds the key JSON-escaped.
    id=$("$cli" permissions list </dev/null 2>&1 | grep -F -B1 "\\\"key\\\":\\\"$key\\\"" |
        sed -n 's/^"\(prm_[^"]*\)".*/\1/p' | head -1)
    [ -n "$id" ] || die "no grant found for $key"
    record=$(permission "$id")
    granted=$(sed -n 's/.*granted: \([0-9]*\).*/\1/p' <<<"$record" | head -1)
    expires=$(sed -n 's/.*expires: \([0-9]*\).*/\1/p' <<<"$record" | head -1)
    [ -n "$granted" ] && [ -n "$expires" ] || die "grant for $key has no expiry: $record"
    lifetime=$((expires - granted))
    echo "grant:         $lifetime s (cap $max_wsl_grant_seconds s)"
    [ "$lifetime" -le "$max_wsl_grant_seconds" ] || die "WSL grant outlives the cap"
    echo "PASS"
    ;;
esac
