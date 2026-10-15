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

# shellcheck disable=SC2086 # FACTORSEAL_CARGO_FEATURES holds cargo flags.
set -- cargo build --locked --target "$RUST_TARGET" --profile "$CARGO_PROFILE" \
    -p factorseal -p factorseal-desktop --bins ${FACTORSEAL_CARGO_FEATURES:-}
# -dead_strip_dylibs keeps unused Nix libraries out of the app.
set -- env \
    CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
    CLANG_MODULE_CACHE_PATH="$CARGO_TARGET_DIR/clang-modules" \
    FACTORSEAL_APPLE_BRIDGE_DIR="$CARGO_BIN_DIR/apple-bridge" \
    FACTORSEAL_BUILD_NUMBER="$CURRENT_PROJECT_VERSION" \
    MACOSX_DEPLOYMENT_TARGET="$MACOSX_DEPLOYMENT_TARGET" \
    NIX_LDFLAGS=-dead_strip_dylibs \
    "$@"

PATH="$PATH:$HOME/.cargo/bin"
if command -v cargo >/dev/null 2>&1; then
    exec "$@"
fi
# Nix-managed machines get cargo from devenv. Start from a clean environment so
# Xcode's SDK and toolchain variables do not reach the Nix toolchain.
exec devenv --no-tui shell --clean=HOME,TMPDIR -- "$@"
