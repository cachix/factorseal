#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out=web/public/desktop
wasm=target/wasm32-unknown-unknown/web/factorseal-desktop.wasm
cargo build -p factorseal-desktop --target wasm32-unknown-unknown --profile web
name="factorseal-desktop-$(sha256sum "$wasm" | cut -c1-16)"
rm -f "$out"/factorseal-desktop*
wasm-bindgen --target web --no-typescript --remove-name-section --out-dir "$out" --out-name "$name" "$wasm"
sed "s/factorseal-desktop\([._]\)/$name\1/g" web/desktop/index.html > "$out/index.html"
node -e '
const { readFileSync, writeFileSync } = require("node:fs");
const { brotliCompressSync, constants } = require("node:zlib");
const file = process.argv[1];
const data = readFileSync(file);
const params = { [constants.BROTLI_PARAM_QUALITY]: 11, [constants.BROTLI_PARAM_LGWIN]: 24, [constants.BROTLI_PARAM_SIZE_HINT]: data.length };
writeFileSync(`${file}.br`, brotliCompressSync(data, { params }));
' "$out/${name}_bg.wasm"
