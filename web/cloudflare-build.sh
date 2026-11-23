#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

build_tools=$(mktemp -d)
trap 'rm -rf "$build_tools"' EXIT

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
    https://sh.rustup.rs -o "$build_tools/rustup-init.sh"
  sh "$build_tools/rustup-init.sh" -y --no-modify-path --profile minimal --default-toolchain none
fi
export PATH="$HOME/.cargo/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.99.0
rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal --target wasm32-unknown-unknown

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  https://github.com/wasm-bindgen/wasm-bindgen/releases/download/0.2.127/wasm-bindgen-0.2.127-x86_64-unknown-linux-musl.tar.gz \
  -o "$build_tools/wasm-bindgen.tar.gz"
printf '%s  %s\n' \
  61d4a7dc85acfa0d2354ccc0b8361928c7e52a746d17f28ebaa795ed3dc1614a \
  "$build_tools/wasm-bindgen.tar.gz" | sha256sum --check --status
tar -xzf "$build_tools/wasm-bindgen.tar.gz" -C "$build_tools" --strip-components=1
export PATH="$build_tools:$PATH"

export CARGO_BUILD_JOBS=2
bash scripts/build-desktop-web.sh
npm --prefix web ci
npm --prefix web run build
