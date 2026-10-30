#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="$root/build/ios-smoke"
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/../Cargo.toml" | head -n 1)
device="$(xcrun simctl list devices available --json |
  jq -r '[.devices[][] | select(.name | startswith("iPhone"))][0].udid // empty')"
if [ -z "$device" ]; then
  echo "no iPhone simulator is available" >&2
  exit 1
fi

"$root/gradlew" -p "$root" --no-daemon :shared:iosSimulatorArm64Test -Pfactorseal.simulator="$device"

"$root/scripts/build-ios-core.sh" Debug
xcodegen --spec "$root/iosApp/project.yml"
xcodebuild -project "$root/iosApp/FactorSeal.xcodeproj" -scheme FactorSeal -configuration Debug \
  -destination "id=$device" -derivedDataPath "$output" CODE_SIGNING_ALLOWED=NO build

app="$output/Build/Products/Debug-iphonesimulator/FactorSeal.app"
if [ "$(plutil -extract CFBundleShortVersionString raw "$app/Info.plist")" != "$version" ]; then
  echo "FactorSeal.app does not have version $version" >&2
  exit 1
fi

xcrun simctl bootstatus "$device" -b
xcrun simctl install "$device" "$app"
pid="$(xcrun simctl launch "$device" com.cachix.factorseal | awk '{print $NF}')"
sleep 20
xcrun simctl io "$device" screenshot "$output/launch.png"
if ! kill -0 "$pid" 2>/dev/null; then
  xcrun simctl spawn "$device" log show --last 2m --style compact --predicate 'process == "FactorSeal"' >&2 || true
  echo "FactorSeal stopped after launch" >&2
  exit 1
fi
