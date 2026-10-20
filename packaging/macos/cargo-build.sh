#!/usr/bin/env bash
# Run by the Cargo target in Factorseal.xcodeproj. Factorseal.xcconfig provides
# the Rust target, profile, features and target directory through the environment.
set -eu

for setting in CARGO_BIN_DIR CARGO_PROFILE CARGO_TARGET_DIR CURRENT_PROJECT_VERSION \
    MACOSX_DEPLOYMENT_TARGET RUST_TARGET; do
    [ -n "${!setting:-}" ] || { echo "error: $setting is not set; run this script from Xcode" >&2; exit 2; }
done
cd "$(dirname "$0")/../.."

# Xcode also exports deployment targets for its other platforms. Clang rejects
# those when compiling the macOS bindings and native dependencies.
unset IPHONEOS_DEPLOYMENT_TARGET TVOS_DEPLOYMENT_TARGET WATCHOS_DEPLOYMENT_TARGET \
    XROS_DEPLOYMENT_TARGET DRIVERKIT_DEPLOYMENT_TARGET

export CLANG_MODULE_CACHE_PATH="$CARGO_TARGET_DIR/clang-modules"
export FACTORSEAL_APPLE_BRIDGE_DIR="$CARGO_BIN_DIR/apple-bridge"
export FACTORSEAL_BUILD_NUMBER="$CURRENT_PROJECT_VERSION"
# -dead_strip_dylibs keeps unused Nix libraries out of the app.
export NIX_LDFLAGS=-dead_strip_dylibs

bash packaging/macos/generate-icons.sh
# shellcheck disable=SC2086 # FACTORSEAL_CARGO_FEATURES holds cargo flags.
exec cargo build --locked --target "$RUST_TARGET" --profile "$CARGO_PROFILE" \
    -p factorseal -p factorseal-desktop --bins ${FACTORSEAL_CARGO_FEATURES:-}
