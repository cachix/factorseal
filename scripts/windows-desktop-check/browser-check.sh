#!/usr/bin/env bash
# Checks the browser extension end to end in Edge or Chrome on Windows, from
# WSL2.
#
#   browser-check.sh [--browser=edge|chrome|both] [--restart-browser] [--only=STEP,...]
#       Builds the extension, loads it into a separate browser profile kept in
#       %LOCALAPPDATA%\FactorSeal-check\<browser>-profile (Edge by default),
#       and drives it against the test vault's Desktop: pairing (first run
#       only), saving a login, resubmitting it unchanged, saving from a
#       registration form, updating a stored login's password (and failing
#       when the login changes during review), filling it, Deny, Escape, a
#       site with no stored login, "Check this page" with and without a login
#       form, a fill that starts while the vault is sealed, a fill held
#       between the choice and its release while the login changes, the
#       profile is disconnected in Settings, or Desktop's wait lapses, and a
#       profile disconnected in Settings without the extension hearing, and
#       restarting the native host, the extension's service worker, Desktop,
#       and the browser while a fill waits; a save interrupted by
#       navigation, denial, closing its tab, disconnecting or sealing; "Save
#       login from this page"; correcting a login; forms that must not offer
#       a save; and that the extension stores none of the submitted values.
#       Desktop's prompt is driven
#       through drive.ps1, so the check takes over the Windows desktop while
#       it runs. --restart-browser closes the test browser first; --only runs
#       just the steps whose names start so (see browser-check.mjs); pairing
#       and saving always run. --browser=both pairs both test browsers and
#       checks that consent never crosses from one to the other: while one
#       browser's request waits, the other is told Desktop is busy, and the
#       approval or denial reaches only the browser that asked.
#
# The test copy of the extension has its site access granted at install:
# the browser's permission dialog cannot be answered through the DevTools
# Protocol. Otherwise it is the extension as built. Chrome ignores
# --load-extension since version 137 and Edge since version 154, so the check
# loads it through the DevTools Protocol (Extensions.loadUnpacked) in both.
set -euo pipefail

restart=no
browser=edge
extra=()
for argument in "$@"; do
    case $argument in
        --browser=edge | --browser=chrome | --browser=both) browser=${argument#--browser=} ;;
        --restart-browser) restart=yes ;;
        --only=?*) extra+=("$argument") ;;
        *) sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
    esac
done

repo=$(cd "$(dirname "$0")/../.." && pwd)
here=$(cd "$(dirname "$0")" && pwd)
die() { echo "FAIL: $*" >&2; exit 1; }

windows_env() { cmd.exe /c "echo %$1%" 2>/dev/null | tr -d '\r'; }
windows_profile=$(wslpath "$(windows_env USERPROFILE)")
windows_tree=${FACTORSEAL_WINDOWS_TREE:-$windows_profile/Projects/factorseal}
cli="$windows_tree/target/release/factorseal.exe"
test_dir="$(windows_env LOCALAPPDATA)\\FactorSeal-check"
extension="$test_dir\\extension-chromium"

command -v node >/dev/null || die "node is missing; run inside devenv shell"
[ -x "$cli" ] || die "no native CLI at $cli; build it with $here/build-windows.sh"

node "$repo/extensions/browser/build.mjs"
target=$(wslpath "$extension")
rm -rf "$target"
mkdir -p "$target"
cp -r "$repo/extensions/browser/dist/chromium/." "$target/"
node -e '
    const fs = require("fs"), path = process.argv[1];
    const manifest = JSON.parse(fs.readFileSync(path, "utf8"));
    manifest.host_permissions = manifest.optional_host_permissions;
    delete manifest.optional_host_permissions;
    fs.writeFileSync(path, JSON.stringify(manifest, null, 1));
' "$target/manifest.json"
echo "extension:     $extension"

"$here/check.sh" test-desktop | sed -n 's/^desktop: *//p; s/^vault: *//p' | sed 's/^/desktop:       /'
desktop_pid=$(powershell.exe -NoProfile -Command "
    Get-CimInstance Win32_Process -Filter \"Name='factorseal-desktop.exe'\" |
        Where-Object { \$_.CommandLine -like '*FactorSeal-check*' } |
        Select-Object -First 1 -ExpandProperty ProcessId" </dev/null | tr -d '\r')
[ -n "$desktop_pid" ] || die "the test Desktop is not running"

# Browsers reach the vault of the Desktop that started last.
host_config="$(wslpath "$(windows_env APPDATA)")/Factorseal/Factorseal/config/browser-host.json"
grep -q 'FactorSeal-check' "$host_config" 2>/dev/null ||
    die "the browser host points at another vault; stop the test Desktop and rerun, so it starts last"

node_windows() {
    powershell.exe -NoProfile -Command "node $(printf "'%s' " "$@")" </dev/null | tr -d '\r'
}

# Starts (or reuses) one test browser and prints its description for
# browser-check.mjs as JSON.
start_browser() {
    local kind=$1 name executable port flags load='' fresh=false profile
    profile="$test_dir\\$kind-profile"
    case $kind in
        edge)
            name=Edge
            executable='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
            port=9333
            flags="'--enable-unsafe-extension-debugging'"
            load=${extension//\\/\\\\}
            ;;
        chrome)
            name=Chrome
            executable='C:\Program Files\Google\Chrome\Application\chrome.exe'
            port=9334
            flags="'--enable-unsafe-extension-debugging'"
            load=${extension//\\/\\\\}
            ;;
    esac
    debugging() {
        powershell.exe -NoProfile -Command "
            try { (Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:$port/json/version).StatusCode } catch { 0 }" </dev/null | tr -d '\r'
    }
    if [ "$restart" = yes ] && [ "$(debugging)" = 200 ]; then
        node_windows "$(wslpath -w "$here/browser-check.mjs")" --browsers="$(encode "[{\"port\":$port}]")" --close=yes >/dev/null || true
        sleep 2
    fi
    if [ "$(debugging)" != 200 ]; then
        powershell.exe -NoProfile -Command "
            Start-Process '$executable' -ArgumentList '--user-data-dir=\"$profile\"', '--remote-debugging-port=$port',
                $flags, '--no-first-run', '--no-default-browser-check', 'about:blank'" </dev/null
        for _ in $(seq 30); do [ "$(debugging)" = 200 ] && break; sleep 0.5; done
        [ "$(debugging)" = 200 ] || die "the test $name did not start with remote debugging on port $port"
        echo "browser:       started the test $name" >&2
        fresh=true
    else
        echo "browser:       reusing the test $name" >&2
    fi
    # The browser process: the one of the test profile without a --type.
    local pid
    pid=$(powershell.exe -NoProfile -Command "
        Get-CimInstance Win32_Process -Filter \"Name='$(basename "${executable//\\//}")'\" |
            Where-Object { \$_.CommandLine -like '*FactorSeal-check*$kind-profile*' -and \$_.CommandLine -notlike '*--type=*' } |
            Select-Object -First 1 -ExpandProperty ProcessId" </dev/null | tr -d '\r')
    [ -n "$pid" ] || die "could not find the test $name's browser process"
    # How to start it again, for the check that restarts the browser.
    printf '{"kind":"%s","port":%s,"pid":"%s","load":"%s","fresh":%s,"executable":"%s","profile":"%s","extension":"%s"}' \
        "$kind" "$port" "$pid" "$load" "$fresh" "${executable//\\/\\\\}" "${profile//\\/\\\\}" "${extension//\\/\\\\}"
}

# Base64: PowerShell drops the double quotes of JSON on the way to Node.
encode() { printf '%s' "$1" | base64 -w0; }
case $browser in
    both)
        edge=$(start_browser edge) || exit 1
        chrome=$(start_browser chrome) || exit 1
        browsers="[$edge,$chrome]"
        ;;
    *) browsers="[$(start_browser "$browser")]" || exit 1 ;;
esac

node_windows "$(wslpath -w "$here/browser-check.mjs")" \
    --browsers="$(encode "$browsers")" \
    --drive="$(wslpath -w "$here/drive.ps1")" \
    --desktopPid="$desktop_pid" \
    --cli="$(wslpath -w "$cli")" \
    --root="$test_dir\\vault" \
    --passwordFile="$test_dir\\password" \
    --foreground="$(wslpath -w "$here/foreground.ps1")" \
    --uiaDump="$(wslpath -w "$here/uia-dump.ps1")" \
    "${extra[@]}"
