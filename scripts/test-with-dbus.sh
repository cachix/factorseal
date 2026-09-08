#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec dbus-run-session --config-file "$repo_root/tests/fixtures/dbus-session.conf" -- env FACTORSEAL_TEST_PRIVATE_DBUS=1 "$@"
