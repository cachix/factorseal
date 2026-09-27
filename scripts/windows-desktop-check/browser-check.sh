#!/usr/bin/env bash
# Checks the browser extension end to end in Edge on Windows, from WSL2.
#
#   browser-check.sh [--restart-browser] [--only=STEP,...]
#       Builds the extension, loads it into a separate Edge profile kept in
#       %LOCALAPPDATA%\FactorSeal-check\edge-profile, and drives it against
#       the test vault's Desktop: pairing (first run only), saving a login,
#       resubmitting it unchanged, filling it, Deny, Escape, a site with no
#       stored login, "Check this page" with and without a login form, and a
#       fill that starts while the vault is sealed. Desktop's prompt is driven
#       through drive.ps1, so the check takes over the Windows desktop while
#       it runs. --restart-browser closes the test Edge first; --only runs
#       just the named steps (see browser-check.mjs), pairing first if needed.
#
# The test copy of the extension has its site access granted at install:
# Edge's permission dialog cannot be answered through the DevTools Protocol.
# Otherwise it is the extension as built.
set -euo pipefail

restart=no
extra=()
for argument in "$@"; do
    case $argument in
        --restart-browser) restart=yes ;;
        --only=?*) extra+=("$argument") ;;
        *) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
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
profile="$test_dir\\edge-profile"
edge='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
port=9333

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

debugging() {
    powershell.exe -NoProfile -Command "
        try { (Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://127.0.0.1:$port/json/version).StatusCode } catch { 0 }" </dev/null | tr -d '\r'
}
node_windows() {
    powershell.exe -NoProfile -Command "node $(printf "'%s' " "$@")" </dev/null | tr -d '\r'
}
if [ "$restart" = yes ] && [ "$(debugging)" = 200 ]; then
    node_windows "$(wslpath -w "$here/browser-check.mjs")" --port="$port" --close=yes >/dev/null || true
    sleep 2
fi
if [ "$(debugging)" != 200 ]; then
    powershell.exe -NoProfile -Command "
        Start-Process '$edge' -ArgumentList '--user-data-dir=\"$profile\"', '--remote-debugging-port=$port',
            '--load-extension=\"$extension\"', '--no-first-run', '--no-default-browser-check', 'about:blank'" </dev/null
    for _ in $(seq 30); do [ "$(debugging)" = 200 ] && break; sleep 0.5; done
    [ "$(debugging)" = 200 ] || die "the test Edge did not start with remote debugging on port $port"
    echo "browser:       started the test Edge"
    extra+=(--fresh=yes)
else
    echo "browser:       reusing the test Edge"
fi

# The browser process: the one of the test profile without a --type.
edge_pid=$(powershell.exe -NoProfile -Command "
    Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" |
        Where-Object { \$_.CommandLine -like '*FactorSeal-check*edge-profile*' -and \$_.CommandLine -notlike '*--type=*' } |
        Select-Object -First 1 -ExpandProperty ProcessId" </dev/null | tr -d '\r')
[ -n "$edge_pid" ] || die "could not find the test Edge's browser process"

node_windows "$(wslpath -w "$here/browser-check.mjs")" \
    --port="$port" \
    --drive="$(wslpath -w "$here/drive.ps1")" \
    --desktopPid="$desktop_pid" \
    --cli="$(wslpath -w "$cli")" \
    --root="$test_dir\\vault" \
    --passwordFile="$test_dir\\password" \
    --foreground="$(wslpath -w "$here/foreground.ps1")" \
    --edgePid="$edge_pid" \
    "${extra[@]}"
