#!/usr/bin/env python3
"""Require fuzzers to exercise the versions in the product's dependency lock."""
from pathlib import Path
import tomllib

root = Path(__file__).resolve().parent.parent
product = tomllib.loads((root / "Cargo.lock").read_text())["package"]
fuzz = tomllib.loads((root / "fuzz/Cargo.lock").read_text())["package"]
versions = {}
for package in product:
    key = package["name"], package.get("source")
    versions.setdefault(key, set()).add(package["version"])
drift = [f'{p["name"]} {p["version"]}' for p in fuzz
         if (allowed := versions.get((p["name"], p.get("source"))))
         and p["version"] not in allowed]
if drift:
    raise SystemExit("Fuzz/product dependency drift: " + ", ".join(drift))
print("Fuzz dependencies match the product lockfile.")
