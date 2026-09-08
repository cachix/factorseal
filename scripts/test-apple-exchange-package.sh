#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
    echo "usage: $0 PACKAGE_TARBALL" >&2
    exit 2
fi
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
tar -xzf "$1" -C "$scratch"
app=$(find "$scratch" -name Factorseal.app -type d -print -quit)
[[ -n "$app" ]]
extension="$app/Contents/PlugIns/FactorSealCredentialProvider.appex"
codesign --verify --deep --strict "$app"
codesign --verify --strict "$extension"
python3 - "$app" <<'PY'
import plistlib
import sys
from pathlib import Path

app = Path(sys.argv[1]) / "Contents"
main = plistlib.loads((app / "Info.plist").read_bytes())
assert main["CFBundleExecutable"] == "factorseal-desktop"
assert main["FactorSealExperimentalCredentialExchange"] is True
assert main["LSMinimumSystemVersion"] == "26.0"
assert len(main["NSUserActivityTypes"]) == 1
extension = plistlib.loads((app / "PlugIns/FactorSealCredentialProvider.appex/Contents/Info.plist").read_bytes())
assert extension["CFBundleIdentifier"] == main["CFBundleIdentifier"] + ".credentials"
assert extension["CFBundleVersion"] == main["CFBundleVersion"]
assert extension["NSExtension"]["NSExtensionPrincipalClass"] == "FactorSealCredentialProvider"
capabilities = extension["NSExtension"]["NSExtensionAttributes"]["ASCredentialProviderExtensionCapabilities"]
assert capabilities == {"SupportsCredentialExchange": True, "SupportedCredentialExchangeVersions": ["1.0"]}
assert (app / "Frameworks/libFactorSealAppleBridge.dylib").is_file()
assert not (app / "embedded.provisionprofile").exists(), "CI package must use local signing"
PY
xcrun swift - "$app/Contents/Info.plist" <<'SWIFT'
import AuthenticationServices
import Foundation
let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
precondition(plist["NSUserActivityTypes"] as? [String] == [ASCredentialExchangeActivity])
SWIFT
symbols=$(nm -gU "$app/Contents/Frameworks/libFactorSealAppleBridge.dylib")
for symbol in install set_unlocked finish export; do
    grep -q "_factorseal_apple_$symbol$" <<<"$symbols"
done
# Load the real Rust executable and its embedded Swift library, without opening
# a vault or using Apple's credential transfer UI.
"$app/Contents/MacOS/factorseal-desktop" --help > /dev/null
"$app/Contents/MacOS/factorseal" --version
echo "Experimental desktop, native bridge, and extension package checks passed."
