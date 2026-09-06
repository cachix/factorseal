#!/usr/bin/env python3
"""Require fuzzers to exercise the versions in the product's dependency lock."""
from pathlib import Path
import tomllib

def dependency_drift(product, fuzz):
    versions = {}
    for package in product:
        versions.setdefault(package["name"], set()).add(
            (package["version"], package.get("source")))
    return [f'{p["name"]} {p["version"]} ({p.get("source", "local")})' for p in fuzz
            if p["name"] in versions
            and (p["version"], p.get("source")) not in versions[p["name"]]]


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    product = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    fuzz = tomllib.loads((root / "fuzz/Cargo.lock").read_text())["package"]
    drift = dependency_drift(product, fuzz)
    if drift:
        raise SystemExit("Fuzz/product dependency drift: " + ", ".join(drift))
    print("Fuzz dependencies match the product lockfile.")
