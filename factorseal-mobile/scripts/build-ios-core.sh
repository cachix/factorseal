#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "${1:-Release}" in
  Debug) profile=release ;;
  *) profile=mobile ;;
esac
output="$root/build/ios"
target_dir="$output/target"

for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  env -i HOME="$HOME" PATH="$HOME/.cargo/bin:$PATH" IPHONEOS_DEPLOYMENT_TARGET=16.0 \
    cargo build --locked --manifest-path "$root/core/Cargo.toml" --package factorseal-mobile \
    --profile "$profile" --target "$target" --target-dir "$target_dir"
done

rm -rf "$output/FactorSealCore.xcframework"
xcodebuild -create-xcframework \
  -library "$target_dir/aarch64-apple-ios/$profile/libfactorseal_mobile.a" -headers "$root/core/include" \
  -library "$target_dir/aarch64-apple-ios-sim/$profile/libfactorseal_mobile.a" -headers "$root/core/include" \
  -output "$output/FactorSealCore.xcframework"
