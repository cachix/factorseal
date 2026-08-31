#!/bin/sh
set -eu

usage() {
    echo "usage: $0 APP_BUNDLE DEPLOYMENT_TARGET" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
app=$1
deployment_target=$2

[ "$(uname -s)" = Darwin ] || {
    echo "macOS app preparation must run on macOS" >&2
    exit 2
}
[ -d "$app/Contents" ] || { echo "app bundle not found: $app" >&2; exit 2; }
[ -f "$app/Contents/Info.plist" ] || { echo "Info.plist not found in $app" >&2; exit 2; }

executable=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist")
main="$app/Contents/MacOS/$executable"
[ -f "$main" ] || { echo "app executable not found: $main" >&2; exit 2; }

# Nixpkgs links against its own libiconv, but that path does not exist on
# another Mac. The SDK exposes the same library from macOS, so use that path
# before signing.
/usr/bin/find "$app/Contents" -type f -print | while IFS= read -r candidate; do
    /usr/bin/file -b "$candidate" | /usr/bin/grep -q 'Mach-O' || continue
    /usr/bin/otool -L "$candidate" | /usr/bin/awk 'NR > 1 { print $1 }' |
        while IFS= read -r dependency; do
            case $dependency in
                /nix/store/*-libiconv-*/lib/libiconv.2.dylib)
                    /usr/bin/install_name_tool -change \
                        "$dependency" /usr/lib/libiconv.2.dylib "$candidate"
                    ;;
            esac
        done
done

# Check every load command, not only LC_LOAD_DYLIB. This catches store-backed
# rpaths and future native dependencies rather than silently shipping them.
/usr/bin/find "$app/Contents" -type f -print | while IFS= read -r candidate; do
    /usr/bin/file -b "$candidate" | /usr/bin/grep -q 'Mach-O' || continue
    if /usr/bin/otool -l "$candidate" | /usr/bin/grep -F '/nix/store/' >/dev/null; then
        echo "Nix store load command remains in $candidate:" >&2
        /usr/bin/otool -l "$candidate" | /usr/bin/grep -F '/nix/store/' >&2
        exit 1
    fi
done

/usr/bin/find "$app/Contents" -type f -print | while IFS= read -r candidate; do
    /usr/bin/file -b "$candidate" | /usr/bin/grep -q 'Mach-O' || continue

    actual_targets=$(/usr/bin/otool -l "$candidate" |
        /usr/bin/awk '$1 == "minos" { print $2 }' | /usr/bin/sort -u)
    [ "$actual_targets" = "$deployment_target" ] || {
        echo "expected macOS deployment target $deployment_target in $candidate, found: $actual_targets" >&2
        exit 1
    }
done

echo "Prepared portable app for macOS $deployment_target"
