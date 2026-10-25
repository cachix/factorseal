import re
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path

LUCIDE = [
    "arrow-right",
    "asterisk",
    "book-open",
    "building-2",
    "calendar",
    "case-sensitive",
    "check",
    "chevron-down",
    "chevron-left",
    "chevron-right",
    "circle-check",
    "circle-user",
    "circle-x",
    "close",
    "copy",
    "ellipsis",
    "external-link",
    "eye",
    "eye-off",
    "file",
    "folder",
    "folder-open",
    "globe",
    "hard-drive",
    "inbox",
    "map",
    "network",
    "palette",
    "plus",
    "redo",
    "settings",
    "square-terminal",
    "star",
    "star-fill",
    "undo-2",
    "user",
]

GLYPHS = [
    "card",
    "clock",
    "close",
    "download",
    "generate",
    "key",
    "lock",
    "mail",
    "mark",
    "mark-micro",
    "paste",
    "pencil",
    "phone",
    "qr-code",
    "refresh",
    "search",
    "tag",
    "transfer",
    "trash",
    "upload",
]

INHERITED = ["fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin", "fill-rule"]
BLACK = "#FF000000"


def local(tag):
    return tag.rsplit("}", 1)[-1]


def number(value):
    text = f"{float(value):.3f}".rstrip("0").rstrip(".")
    return text if text not in ("", "-0") else "0"


def rect(node):
    x, y = float(node.get("x", 0)), float(node.get("y", 0))
    w, h = float(node.get("width")), float(node.get("height"))
    r = min(float(node.get("rx", node.get("ry", 0))), w / 2, h / 2)
    if r == 0:
        return f"M{number(x)},{number(y)}h{number(w)}v{number(h)}h{number(-w)}z"
    arc = f"a{number(r)},{number(r)} 0 0,1"
    return (
        f"M{number(x + r)},{number(y)}h{number(w - 2 * r)}{arc} {number(r)},{number(r)}"
        f"v{number(h - 2 * r)}{arc} {number(-r)},{number(r)}h{number(-(w - 2 * r))}"
        f"{arc} {number(-r)},{number(-r)}v{number(-(h - 2 * r))}{arc} {number(r)},{number(-r)}z"
    )


def circle(node):
    cx, cy, r = (float(node.get(key)) for key in ("cx", "cy", "r"))
    arc = f"a{number(r)},{number(r)} 0 1,0"
    return f"M{number(cx - r)},{number(cy)}{arc} {number(2 * r)},0{arc} {number(-2 * r)},0z"


def points(node, closed):
    values = [number(value) for value in re.split(r"[\s,]+", node.get("points").strip())]
    pairs = [f"{values[i]},{values[i + 1]}" for i in range(0, len(values), 2)]
    return "M" + " L".join(pairs) + ("z" if closed else "")


def geometry(node):
    tag = local(node.tag)
    if tag == "path":
        return node.get("d")
    if tag == "rect":
        return rect(node)
    if tag == "circle":
        return circle(node)
    if tag == "line":
        return f"M{number(node.get('x1'))},{number(node.get('y1'))}L{number(node.get('x2'))},{number(node.get('y2'))}"
    if tag == "polyline":
        return points(node, False)
    if tag == "polygon":
        return points(node, True)
    return None


def walk(node, style, paths):
    style = {**style, **{key: node.get(key) for key in INHERITED if node.get(key) is not None}}
    data = geometry(node)
    if data is not None:
        attributes = [f'android:pathData="{" ".join(data.split())}"']
        if style.get("fill", "black") != "none":
            attributes.append(f'android:fillColor="{BLACK}"')
            if style.get("fill-rule") == "evenodd":
                attributes.append('android:fillType="evenOdd"')
        if style.get("stroke", "none") != "none":
            attributes.append(f'android:strokeColor="{BLACK}"')
            attributes.append(f'android:strokeWidth="{number(style.get("stroke-width", 1))}"')
            attributes.append(f'android:strokeLineCap="{style.get("stroke-linecap", "butt")}"')
            attributes.append(f'android:strokeLineJoin="{style.get("stroke-linejoin", "miter")}"')
        paths.append("    <path\n        " + "\n        ".join(attributes) + " />")
    for child in node:
        if local(child.tag) not in ("title", "desc", "defs"):
            walk(child, style, paths)


def convert(source, target):
    root = ElementTree.parse(source).getroot()
    _, _, width, height = (float(value) for value in root.get("viewBox").split())
    paths = []
    walk(root, {}, paths)
    target.write_text(
        '<vector xmlns:android="http://schemas.android.com/apk/res/android"\n'
        f'    android:width="24dp"\n    android:height="{number(24 * height / width)}dp"\n'
        f'    android:viewportWidth="{number(width)}"\n    android:viewportHeight="{number(height)}">\n'
        + "\n".join(paths)
        + "\n</vector>\n"
    )


def main():
    lucide = Path(sys.argv[1])
    root = Path(__file__).resolve().parent.parent
    logo = root.parent / "assets" / "logo"
    output = root / "shared" / "src" / "commonMain" / "composeResources" / "drawable"
    output.mkdir(parents=True, exist_ok=True)
    for name in LUCIDE:
        convert(lucide / f"{name}.svg", output / f"icon_{name.replace('-', '_')}.xml")
    for name in GLYPHS:
        convert(logo / f"factorseal-{name}.svg", output / f"glyph_{name.replace('-', '_')}.xml")


main()
