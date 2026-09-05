#!/usr/bin/env python3
"""Fail closed on RustSec findings, except exact, unexpired maintenance entries."""

import argparse
import datetime
import json
import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def check(report, exceptions, today):
    errors = []
    allowed = {}
    for item in exceptions:
        key = (item["id"], item["package"], item["version"])
        if key in allowed:
            errors.append(f"Duplicate exception: {key}")
        if not item.get("owner") or not item.get("reason") or not item.get("migration"):
            errors.append(f"Exception needs owner, reason, and migration: {key}")
        if item["expires"] <= today:
            errors.append(f"Expired exception: {key}")
        allowed[key] = item
    vulnerabilities = report["vulnerabilities"]
    if vulnerabilities["found"] or vulnerabilities["list"]:
        errors.append("RustSec reports vulnerabilities; maintenance exceptions cannot allow them")
    seen = set()
    for kind, warnings in report["warnings"].items():
        for warning in warnings:
            package = warning["package"]
            advisory = warning.get("advisory") or {}
            key = (advisory.get("id"), package["name"], package["version"])
            if kind != "unmaintained" or advisory.get("informational") != "unmaintained" or key not in allowed:
                errors.append(f"Unapproved {kind} finding: {key}")
            else:
                seen.add(key)
    for key in allowed.keys() - seen:
        errors.append(f"Remove obsolete exception: {key}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-binary", help="explicit cargo-audit executable for development")
    args = parser.parse_args()
    command = [args.audit_binary, "audit"] if args.audit_binary else ["cargo", "audit"]
    process = subprocess.run(command + ["--json"], cwd=ROOT, capture_output=True, text=True, check=False)
    if process.returncode not in (0, 1):
        raise RuntimeError(process.stderr or "cargo audit failed")
    report = json.loads(process.stdout)
    exceptions = tomllib.loads((ROOT / "security/dependency-exceptions.toml").read_text())["exception"]
    errors = check(report, exceptions, datetime.datetime.now(datetime.UTC).date())
    # Any nonzero audit exit must fail, even if a future schema changes how it
    # represents a vulnerability, yanked dependency, or operational failure.
    if process.returncode:
        errors.append("cargo audit returned a nonzero status")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if exceptions:
        print(f"No reported vulnerabilities; {len(exceptions)} explicit maintenance exceptions expire on "
              f"{min(item['expires'] for item in exceptions)}")
    else:
        print("No reported vulnerabilities or maintenance warnings")
    for item in exceptions:
        print(f"  {item['id']} {item['package']} {item['version']}: {item['migration']}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        print(f"Dependency security check failed: {error}", file=sys.stderr)
        sys.exit(1)
