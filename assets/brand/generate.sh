#!/usr/bin/env bash
# Generate deterministic color variants and application icons from the two masters.
set -euo pipefail
brand_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$brand_dir/../.." && pwd)"
logo_dir="$repo_dir/assets/logo"

for variant in ink paper; do
  color='#151515'
  if [[ "$variant" == paper ]]; then color='#F7F3EA'; fi
  sed "s/currentColor/$color/g" "$logo_dir/factorseal-mark.svg" > "$logo_dir/factorseal-mark-$variant.svg"
  sed "s/currentColor/$color/g" "$logo_dir/factorseal-mark-micro.svg" > "$logo_dir/factorseal-mark-micro-$variant.svg"
done

for variant in ink paper; do
  color='#151515'
  if [[ "$variant" == paper ]]; then color='#F7F3EA'; fi
  {
    cat <<'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 650 160" role="img" aria-labelledby="title description">
  <title id="title">FactorSeal</title>
  <desc id="description">The FactorSeal chip mark and wordmark in a horizontal lockup.</desc>
SVG
    sed -n '/<g fill=/,/<\/g>/p' "$logo_dir/factorseal-mark-$variant.svg"
    printf '  <text x="174" y="104" fill="%s" font-family="system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif" font-size="72" font-weight="600" letter-spacing="-2.5">FactorSeal</text>\n</svg>\n' "$color"
  } > "$logo_dir/factorseal-lockup-$variant.svg"
done

cp "$logo_dir/factorseal-mark-micro-ink.svg" "$logo_dir/dev.factorseal.Desktop-symbolic.svg"
cp "$logo_dir/factorseal-mark-micro-paper.svg" "$logo_dir/dev.factorseal.Desktop-light-symbolic.svg"

# A fixed Paper tile gives the Ink mark contrast on any desktop background.
{
  cat <<'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 160" role="img" aria-labelledby="title description">
  <title id="title">FactorSeal application icon</title>
  <desc id="description">An Ink chip and stepped keyhole on a Paper application tile.</desc>
  <rect width="160" height="160" rx="34" fill="#F7F3EA"/>
  <g transform="translate(16 16) scale(.8)">
SVG
  sed -n '/<g fill=/,/<\/g>/p' "$logo_dir/factorseal-mark-ink.svg"
  printf '  </g>\n</svg>\n'
} > "$logo_dir/factorseal-app-icon.svg"

for spec in '150 Square150x150Logo' '44 Square44x44Logo' '50 StoreLogo'; do
  read -r size name <<< "$spec"
  magick -background none -density 384 "$logo_dir/factorseal-app-icon.svg" \
    -resize "${size}x${size}" -strip "PNG32:$repo_dir/packaging/windows/msix/Assets/$name.png"
done

magick -background none -density 384 "$logo_dir/factorseal-app-icon.svg" \
  -resize 512x512 -strip "PNG32:$logo_dir/factorseal-app-icon-512.png"

for variant in ink paper; do
  magick -background none -density 192 "$logo_dir/factorseal-mark-micro-$variant.svg" \
    -resize 32x32 -strip "PNG32:$logo_dir/factorseal-tray-$variant.png"
done

printf 'Generated logo colors, symbolic icons, and application icons.\n'
