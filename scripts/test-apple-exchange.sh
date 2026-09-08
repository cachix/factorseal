#!/usr/bin/env bash
# SDK and file-format tests only; no vault, signing identity, or Apple account.
set -euo pipefail
umask 077

if [[ $(uname -s) != Darwin ]]; then
    echo "Apple credential exchange tests require macOS 26+ and Xcode 26+." >&2
    exit 2
fi

os_version=$(sw_vers -productVersion)
if (( ${os_version%%.*} < 26 )); then
    echo "macOS 26+ is required; found $os_version." >&2
    exit 2
fi
xcode_version=$(xcodebuild -version)
xcode_major=$(awk '/^Xcode / { split($2, version, "."); print version[1] }' <<< "$xcode_version")
if [[ ! $xcode_major =~ ^[0-9]+$ ]] || (( xcode_major < 26 )); then
    echo "Select Xcode 26+ using DEVELOPER_DIR or xcode-select." >&2
    exit 2
fi
sdk_version=$(xcrun --sdk macosx --show-sdk-version)
if (( ${sdk_version%%.*} < 26 )); then
    echo "The selected Xcode must include the macOS 26+ SDK; found $sdk_version." >&2
    exit 2
fi
command -v cargo >/dev/null || { echo "Install the repository's Rust toolchain first." >&2; exit 2; }

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
results_root="$repo_root/platform/apple/.build/credential-exchange-results"
mkdir -p "$results_root"
results_dir=$(mktemp -d "$results_root/run.XXXXXX")
export FACTORSEAL_TEST_APPLE_CXF_OUTPUT="$results_dir/apple-roundtrip.json"

{
    sw_vers
    xcodebuild -version
    xcrun --sdk macosx --show-sdk-version
    xcrun --find swift
    xcrun swift --version
    cargo --version
    git rev-parse HEAD
    if ! git diff --quiet || [[ -n $(git ls-files --others --exclude-standard) ]]; then
        echo "Working tree contains local changes."
    fi
} 2>&1 | tee "$results_dir/environment.log"

xcrun swift test --package-path platform/apple -Xswiftc -warnings-as-errors 2>&1 | tee "$results_dir/swift-tests.log"
if [[ ! -s $FACTORSEAL_TEST_APPLE_CXF_OUTPUT ]]; then
    echo "Swift did not produce the required synthetic CXF roundtrip artifact." >&2
    exit 1
fi
cargo test --locked --no-default-features --features transfer --lib transfer:: \
    2>&1 | tee "$results_dir/rust-transfer-tests.log"
cargo test --locked --no-default-features --features transfer --lib \
    transfer::cxf::tests::apple_sdk_roundtrip -- --ignored --exact \
    2>&1 | tee "$results_dir/rust-apple-roundtrip.log"

echo "Apple SDK and Rust interoperability checks passed. Results: $results_dir"
echo "Live Apple Passwords transfer is a separate signed-app acceptance test."
