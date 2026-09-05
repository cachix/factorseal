# FactorSeal brand

FactorSeal is the local vault for secrets used by people, applications, and
developer tools. It should feel like dependable open-source infrastructure on
your own machine—not a remote security service.

## Positioning

**Your secrets stay here.**

- Local-first: the vault and its authorization boundary live on the device.
- Hardware-rooted: supported platforms bind vault access to device hardware.
- Understandable: say what is protected, where it lives, and when it is open.
- Quietly trustworthy: no fear-based copy, security theater, or cloud imagery.

## Mark

The FactorSeal mark is a filled, softly rounded hardware chip with two substantial
pins per side and a stepped keyhole in negative space.
The chip represents the local device and its hardware root of trust. The
keyhole represents a sealed secret without promising a particular biometric or
physical key. Its circular head and square shoulders evoke a machined opening.
The stepped keyhole is the distinguishing detail; preserve it in every variant.

The canonical asset is [`assets/logo/factorseal-mark.svg`](assets/logo/factorseal-mark.svg).
Keep the mark one color. Do not fill the keyhole with an accent color, put the
mark inside a shield, add an outer keyline, or redraw it as a generic padlock.

### Sizes and clear space

- Use the primary mark at 32 CSS pixels and above.
- Use [`factorseal-mark-micro.svg`](assets/logo/factorseal-mark-micro.svg) at
  16–24 CSS pixels. This optical variant has a larger opening and pins aligned
  to a 16-pixel grid. Do not reduce the primary artwork for a 16-pixel icon.
- For intermediate sizes below 32 pixels, use the small variant. Avoid marks
  smaller than 16 pixels.
- Keep at least one pin-width of clear space around the visible silhouette:
  16 units on the primary 160-unit grid, or 2 units on the small 16-unit grid.
  The primary viewBox includes this space; the small viewBox needs one extra
  unit of layout padding on every side where surrounding content is present.
- Keep the mark upright and preserve its aspect ratio.

### Color and file formats

The `currentColor` master is for inline SVG or renderers that explicitly set
its foreground. An SVG used through HTML `<img>` does not inherit the parent
element's CSS color. Use the explicit `-ink.svg` and `-paper.svg` exports there.
The keyhole is a true cutout using an even-odd path; it needs no mask or
background-colored overlay.

Use the Ink export on light surfaces and the Paper export on dark surfaces.
When the surrounding background is unknown, use the application tile.

### Application and tray icons

[`factorseal-app-icon.svg`](assets/logo/factorseal-app-icon.svg) places the Ink
mark on a fixed Paper tile with rounded corners. The tile gives the mark its
own contrasting surface on light and dark desktops. It is an application
container, not an extra outline around the standalone mark.

Linux application packaging uses this tile. Windows exports are provided at
44, 50, and 150 pixels, plus a general 512-pixel PNG. Tray icons remain
transparent, using Ink on light panels and Paper on dark panels. The Linux
symbolic assets use the small mark. The runtime tray PNGs are generated from
that same small master at 32 pixels for high-density 16-pixel panels.

### Wordmark

Write **FactorSeal**, with a capital F and S, in one color. Pair it with the
mark at medium or semibold weight and slightly tight spacing. The horizontal
lockup exports use live system-font text and can vary across platforms;
convert that text to outlines in a design editor before sending final artwork
to a print vendor. Do not squeeze the wordmark or put initials in the keyhole.

### Brand board and exports

Open [`assets/brand/index.html`](assets/brand/index.html) for the visual guide,
before/after comparison, interactive light/dark size previews, and downloads.
It is an offline document with no external fonts or services.

Regenerate fixed-color marks, lockups, symbolic icons, and PNG application
icons from the two masters with ImageMagick installed:

```console
bash assets/brand/generate.sh
```

Edit the primary and small masters, then regenerate. The existing study
files are historical concepts, not approved production assets.

## Color

| Token | Value | Use |
| --- | --- | --- |
| Ink | `#151515` | Primary mark, type, controls, selected navigation |
| Paper | `#F7F3EA` | Primary light canvas and negative space |
| Surface | `#FFFCF6` | Cards and raised light surfaces |
| Quiet | `#68635B` | Supporting text |
| Border | `#D9D2C7` | Dividers and control outlines |

Dark surfaces invert Ink and Paper. The mark remains one color.

Green and red are product-state colors, not brand colors. Green means the vault
is currently unsealed; red is reserved for errors and destructive outcomes.
Neither belongs in the permanent logo.

## Typography

Use the operating system's sans-serif UI family. This keeps Desktop native and
avoids shipping a branding font solely for appearance. Prefer medium or
semibold weights, sentence case, short labels, and generous spacing. Use the
system monospace family only for commands, addresses, and identifiers.

## Interface language

- Prefer direct state: “Vault is sealed”, “Vault is unsealed”, “Sealing vault…”
- Prefer concrete actions: “Unlock vault”, “Seal now”, “Create vault”
- Explain security in plain language and link to the deeper threat model.
- Never imply fingerprint unlock is secure where the platform cannot release a
  hardware-bound secret from biometric authorization.
- Refer to the product as **FactorSeal** and the application as
  **FactorSeal Desktop**.
