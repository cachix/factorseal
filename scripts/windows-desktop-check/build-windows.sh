#!/usr/bin/env bash
# Builds and checks FactorSeal natively on Windows, driven from WSL2.
#
#   build-windows.sh [release] [--broker]
#       Mirror this checkout to the Windows copy, then build release binaries
#       there: Desktop, and the CLI with its helpers and SecretSpec provider.
#       Refuses to start while Desktop or the CLI runs, since Windows locks
#       their executables.
#   build-windows.sh check [--broker]
#       Mirror, then run clippy and Desktop's tests natively. Leaves the
#       release executables alone, so it can run while Desktop is open.
#   --broker also cross-compiles the WSL broker on the WSL side.
#
# Desktop cannot be cross-compiled (its renderer needs Windows' shader
# compiler), so the Windows copy is built in place through interop. The copy
# defaults to %USERPROFILE%\Projects\factorseal; override it with
# FACTORSEAL_WINDOWS_TREE (a WSL path).
set -euo pipefail

mode=release
broker=no
for argument in "$@"; do
    case $argument in
        release | check) mode=$argument ;;
        --broker) broker=yes ;;
        *) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
    esac
done

repo=$(cd "$(dirname "$0")/../.." && pwd)
windows_profile=$(wslpath "$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')")
windows_tree=${FACTORSEAL_WINDOWS_TREE:-$windows_profile/Projects/factorseal}
# The features release packaging uses, plus the SecretSpec provider, which
# packaging leaves out until its IPC crate is published (docs/development.md).
cli_features=vault,cli,hardware,secretspec-provider,personal-sync-network,browser

die() { echo "FAIL: $*" >&2; exit 1; }

# Runs PowerShell commands in the Windows copy and returns cargo's exit code.
# Native stderr arrives as error records; print their text, not their type.
windows() {
    powershell.exe -NoProfile -Command "
        Set-Location '$(wslpath -w "$windows_tree")'
        $1 2>&1 | ForEach-Object {
            if (\$_ -is [System.Management.Automation.ErrorRecord]) { \$_.Exception.Message } else { \$_ }
        }
        exit \$LASTEXITCODE" | tr -d '\r'
}

if [ "$mode" = release ]; then
    running=$(powershell.exe -NoProfile -Command \
        "Get-Process factorseal, factorseal-desktop, factorseal-browser -ErrorAction SilentlyContinue | ForEach-Object { \"\$(\$_.Name) (pid \$(\$_.Id))\" }" |
        tr -d '\r' || true) # Get-Process exits 1 when nothing matches.
    [ -z "$running" ] || die "quit FactorSeal first (tray icon, Quit); running: ${running//$'\n'/, }"
fi

mkdir -p "$windows_tree"
echo "Mirroring $repo to $windows_tree"
set +e
# devenv's generated .claude/ and .mcp.json link into /nix/store, which Windows
# cannot open. Robocopy retries an unreadable file a million times by default,
# so /R and /W make any such file fail within seconds instead of hanging.
/mnt/c/Windows/System32/robocopy.exe "$(wslpath -w "$repo")" "$(wslpath -w "$windows_tree")" \
    /MIR /XD .git target .claude .devenv /XF .mcp.json /R:1 /W:1 \
    /NJH /NJS /NDL /NP /NFL >/dev/null
copied=$?
set -e
# Robocopy exit codes below 8 mean success; 1 means files were copied.
[ "$copied" -lt 8 ] || die "robocopy failed with exit code $copied"

case $mode in
release)
    echo "Building Desktop"
    windows "cargo build --locked --release -p factorseal-desktop"
    echo "Building the CLI and its helpers"
    windows "cargo build --locked --release --no-default-features --features $cli_features --bin factorseal --bin factorseal-parser --bin factorseal-network --bin factorseal-browser"
    ;;
check)
    echo "Running clippy"
    windows "cargo clippy --locked -p factorseal-desktop --all-targets -- -D warnings"
    windows "cargo clippy --locked --no-default-features --features $cli_features --bins -- -D warnings"
    echo "Running Desktop's tests"
    windows "cargo test --locked -p factorseal-desktop"
    ;;
esac

if [ "$broker" = yes ]; then
    echo "Cross-compiling the WSL broker"
    (cd "$repo" && devenv shell -- cargo xwin build --locked --release \
        --target x86_64-pc-windows-msvc --bin factorseal-wsl-broker --features vault-client)
fi

if [ "$mode" = release ]; then
    echo
    for binary in factorseal-desktop factorseal factorseal-parser factorseal-network factorseal-browser; do
        stat -c "%y  %n" "$windows_tree/target/release/$binary.exe" | cut -c1-19,36-
    done
fi
echo "OK"
