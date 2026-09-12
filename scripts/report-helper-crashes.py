#!/usr/bin/env python3
"""Print bounded macOS helper crash summaries for native CI.

Only OS exception codes and symbol names are emitted. Register state, memory,
application-specific payloads, and environment contents are never included.
"""
import json
from pathlib import Path


def report(path):
    if path.stat().st_size > 8 * 1024 * 1024:
        print(f"{path.name}: report exceeds size limit")
        return
    content = path.read_text()
    decoder = json.JSONDecoder()
    first, end = decoder.raw_decode(content)
    crash = json.loads(content[end:]) if content[end:].strip() else first
    print(path.name)
    for category, fields in (
        ("exception", ("type", "signal", "codes")),
        ("termination", ("namespace", "code", "indicator")),
    ):
        value = crash.get(category, {})
        print(category, json.dumps({key: value[key] for key in fields if key in value}))
    images = crash.get("usedImages", [])
    for thread in crash.get("threads", []):
        if not thread.get("triggered"):
            continue
        for frame in thread.get("frames", [])[:24]:
            index = frame.get("imageIndex", -1)
            name = images[index].get("name", "unknown") if 0 <= index < len(images) else "unknown"
            print(json.dumps({"image": name, "symbol": frame.get("symbol", "unresolved")}))


def main():
    paths = []
    for directory in (Path.home() / "Library/Logs/DiagnosticReports", Path("/Library/Logs/DiagnosticReports")):
        paths.extend(directory.glob("factorseal-net*.ips"))
    if not paths:
        print("No factorseal-network crash reports were produced.")
    for path in sorted(paths, key=lambda path: path.stat().st_mtime, reverse=True)[:4]:
        try:
            report(path)
        except (OSError, ValueError, TypeError, KeyError) as error:
            print(f"{path.name}: could not read crash summary ({type(error).__name__})")


if __name__ == "__main__":
    main()
