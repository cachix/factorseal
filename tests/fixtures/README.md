Password-manager import/export samples and their provenance are in
[`transfer/`](transfer/README.md).

`keyring-v1.factorseal` contains synthetic keyring metadata and a synthetic value.
It was generated using the production archive encoder from commit
`c9ca725f19ba40aceab495a041a101108c9fc1c6`, before the v2 restore fix.

Passphrase: `synthetic archive orchard violet lantern 2026`.
SHA-256: `5b793cc0c30eefdcf853533f214f259a82c88abbe03c2fef53d8d03cf557cbf9`.

To regenerate, copy `keyring-v1-generator.rs` to `examples/release_v1_fixture.rs`
in a checkout of that commit and run:

```
cargo run --example release_v1_fixture --all-features -- /tmp/keyring-v1.factorseal
```

Encryption uses random salt and nonce, so regeneration produces a different hash.
No user data or real credentials are included.
