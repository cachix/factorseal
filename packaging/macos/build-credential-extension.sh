#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 APP_BUNDLE" >&2; exit 2; }
[ "$(uname -s)" = Darwin ] || { echo "extension builds require macOS and Xcode 26+" >&2; exit 2; }
app=$1
script_dir=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
repo_root=$(CDPATH='' cd -P "$script_dir/../.." && pwd)
extension="$app/Contents/PlugIns/FactorSealCredentialProvider.appex"
mkdir -p "$extension/Contents/MacOS"
cp "$repo_root/platform/apple/Extension/Info.plist" "$extension/Contents/Info.plist"
version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist")
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $version" "$extension/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $version" "$extension/Contents/Info.plist"
xcrun swiftc -parse-as-library -emit-executable \
    -target "$(uname -m)-apple-macosx26.0" \
    -application-extension -module-name FactorSealCredentialProvider \
    -Xlinker -e -Xlinker _NSExtensionMain \
    "$repo_root/platform/apple/Extension/CredentialProvider.swift" \
    -o "$extension/Contents/MacOS/FactorSealCredentialProvider"
/usr/bin/plutil -lint "$extension/Contents/Info.plist"
