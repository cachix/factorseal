#!/usr/bin/env bash
# Run by the app targets in Factorseal.xcodeproj after the Cargo target.
# Copies the Rust executables into the app bundle and stages the helpers for
# Xcode's embed phases.
set -eu

variant=${1:?expected desktop or credential-exchange}
[ "$FACTORSEAL_VARIANT" = "$variant" ] || {
    echo "error: this target needs a $variant configuration, not $CONFIGURATION" >&2
    exit 2
}
bundle_executables="$TARGET_BUILD_DIR/$EXECUTABLE_FOLDER_PATH"
mkdir -p "$bundle_executables"
cp -f "$CARGO_BIN_DIR/factorseal-desktop" "$TARGET_BUILD_DIR/$EXECUTABLE_PATH"
# The CLI runs from the worker bundle. Keep the documented path to it.
ln -sfn ../Helpers/FactorsealWorker.app/Contents/MacOS/factorseal "$bundle_executables/factorseal"

# Xcode signs embedded helpers on copy and keeps their identifier, runtime
# flag and entitlements, so attach those with an ad-hoc signature here.
for helper in factorseal-parser factorseal-network factorseal-browser; do
    cp -f "$CARGO_BIN_DIR/$helper" "$BUILT_PRODUCTS_DIR/$helper"
    /usr/bin/codesign --force --sign - --identifier "dev.$helper" --options runtime \
        --entitlements "$SRCROOT/FactorsealRuntime.entitlements" "$BUILT_PRODUCTS_DIR/$helper"
done
if [ "$variant" = credential-exchange ]; then
    cp -f "$CARGO_BIN_DIR/apple-bridge/libFactorSealAppleBridge.dylib" "$BUILT_PRODUCTS_DIR/"
fi
