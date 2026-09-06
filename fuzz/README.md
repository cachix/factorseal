# Parser fuzzing

The isolated Cargo workspace exercises production parsers without hardware or
real vault files. `factorseal/fuzzing` exposes only synthetic harness entry
points; normal builds do not enable it. The separate lockfile must use the same
dependency versions as the product (`scripts/check-fuzz-lock.py`). When updating
dependencies, copy the product lockfile into `fuzz/Cargo.lock`, then regenerate
the fuzz lockfile with the seed command below and review its diff.

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly run --locked --manifest-path fuzz/Cargo.toml --bin seed-corpus -- fuzz/corpus
cargo +nightly fuzz run metadata -- -max_total_time=60 -max_len=1048576 -rss_limit_mb=2048 -timeout=10
```

Install the nightly toolchain first. The commands follow the
[cargo-fuzz workflow](https://rust-fuzz.github.io/book/cargo-fuzz.html).
The default address sanitizer, overflow checks and debug assertions remain
enabled. `--dev` can reduce local build time for a smoke run.

| Target | Production parsing and validation |
| --- | --- |
| metadata | JSON, versions, identities, profiles, factors, wrapped-key structure |
| protocol | Requests, responses, addresses, grants, application context, byte bounds |
| document | Automerge snapshots, legacy migration, record decoding, personal entry JSON |
| history | History JSON, record versions, sequence and partition validation |
| envelope | Snapshot headers, AEAD rejection, root-wrapped keys, TPM/Hello envelopes and TPM response codec |
| commit_chain | Commit JSON, transcript digest and ML-DSA signature verification |
| secret_service | DH negotiation, public-key bounds, IV and CBC/PKCS#7 parsing |
| archive | Encrypted and plaintext archive JSON, KDF limits and base64 components |
| transfer | Bitwarden JSON, 1Password/KeePass CSV and personal records |
| bootstrap | Length-prefixed inherited-pipe messages and typed bootstrap JSON |

Seeds include valid synthetic metadata, documents, encrypted snapshots and
signed commits, so mutation reaches validation past the outer codec. Archive
fuzzing does not run the expensive password KDF; normal archive tests cover
authenticated encryption/decryption. D-Bus framing remains provided by zbus;
native Secret Service integration tests cover the adapter.

CI runs every target on pushes and pull requests, and for ten minutes per
target daily. It restores per-target corpora, enforces input/RSS/time limits,
and uploads crash artifacts on failure. A discovered crash, timeout or OOM
fails that target. Reproduce with `cargo +nightly fuzz run TARGET ARTIFACT`,
minimize with `cargo +nightly fuzz tmin TARGET ARTIFACT`, add a regression test,
and retain the minimized synthetic input. Never seed with production vaults or
credentials, or upload such data as a crash artifact.

Resolved synthetic crashes are committed under `regressions/TARGET/` and
copied into the corpus by `seed-corpus`, so new campaigns retain them even
without a cache. The malformed bundle counter fixture is covered by
[Automerge PR #1540](https://github.com/automerge/automerge/pull/1540); the
product and fuzz lockfiles pin the same patched fork commit. The lock check
compares dependency sources and Git revisions as well as version numbers.
Manual workflow runs default to 600 seconds per target and accept a `seconds`
input for longer campaigns within the job timeout.

Fuzzing is continuing evidence, not proof that all malformed inputs are safe.
Dependency-internal decompression and allocation behavior is also subject to
the harness limits; production embedders must isolate untrusted workloads.
