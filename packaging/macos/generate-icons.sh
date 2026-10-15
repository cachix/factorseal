#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
source_icon=assets/logo/factorseal-app-icon.svg
appiconset=packaging/macos/Assets.xcassets/AppIcon.appiconset

for size in 16 32 128 256 512; do
  for scale in 1 2; do
    suffix=''
    if [[ "$scale" == 2 ]]; then suffix='@2x'; fi
    output="$appiconset/icon_${size}x${size}${suffix}.png"
    if [[ -f "$output" && "$output" -nt "$source_icon" && "$output" -nt packaging/macos/generate-icons.sh ]]; then
      continue
    fi
    pixels=$((size * scale))
    magick -background none -density 768 "$source_icon" \
      -resize "${pixels}x${pixels}" -strip "PNG32:$output"
  done
done
