"""Run upstream transport conformance against the real Factorseal executable."""

import argparse
import json
import pathlib
import subprocess
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, type=pathlib.Path)
    parser.add_argument("--source", type=pathlib.Path, help="existing pinned SecretSpec checkout")
    args = parser.parse_args()
    endpoint = args.endpoint.resolve(strict=True)
    dependency = tomllib.loads((ROOT / "Cargo.toml").read_text())["dependencies"]["secretspec-ipc"]
    with tempfile.TemporaryDirectory(prefix="factorseal-conformance-") as temporary:
        temporary = pathlib.Path(temporary)
        source = args.source.resolve() if args.source else temporary / "secretspec"
        if not args.source:
            run("git", "init", "--quiet", str(source))
            run("git", "-C", str(source), "fetch", "--quiet", "--depth=1", dependency["git"], dependency["rev"])
            run("git", "-C", str(source), "checkout", "--quiet", "--detach", "FETCH_HEAD")
        revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if revision != dependency["rev"]:
            parser.error("SecretSpec checkout does not match Cargo.toml's pinned revision")
        target = ROOT / "target" / "secretspec-conformance"
        run("cargo", "build", "--locked", "--target-dir", str(target),
            "-p", "secretspec-ipc-conformance", "--bin", "secretspec-ipc-conformance",
            "--bin", "ipc-provider-conformance-driver", cwd=source)
        profile = temporary / "profile.json"
        profile.write_text(json.dumps({
            "schema_version": 1,
            "kind": "transport_only",
            "scheme": "factorseal",
            "uri": "factorseal://default",
            "provider_name": "factorseal",
            "expected_methods": [
                "provider.resolve_address", "provider.get", "provider.exists",
                "provider.set", "provider.set_expiring", "provider.delete",
                "provider.check_writable", "provider.check_deletable",
                "provider.describe_write_target",
            ],
            "arguments": ["--root", str(temporary / "vault"), "provider"],
            "environment": {},
        }))
        run(str(target / "debug" / "secretspec-ipc-conformance"), "run", "provider-endpoint",
            str(target / "debug" / "ipc-provider-conformance-driver"),
            "--implementation", "endpoint", "--endpoint", str(endpoint),
            "--profile", str(profile), cwd=source)


if __name__ == "__main__":
    main()
