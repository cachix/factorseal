#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=web/public/desktop
cargo build -p factorseal-desktop --target wasm32-unknown-unknown --profile web
wasm-bindgen --target web --no-typescript --remove-name-section --out-dir "$out" \
  target/wasm32-unknown-unknown/web/factorseal-desktop.wasm
