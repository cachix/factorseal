# secret-service-protocol

Pure-Rust Secret Service session negotiation and payload protection, independent
of D-Bus, storage, and access policy.

```toml
[dependencies]
secret-service-protocol = "0.1"
```

The crate implements the `plain` and
`dh-ietf1024-sha256-aes128-cbc-pkcs7` session algorithms. `Session::open`
negotiates a server-side session and returns the reply for `OpenSession`.
`Session::encrypt` and `Session::decrypt` convert between secret values and
wire payloads. AES session keys and payload value buffers are zeroized on drop.

```rust
use secret_service_protocol::{ALGORITHM_PLAIN, Session, SessionOutput};

let (session, output) = Session::open(ALGORITHM_PLAIN, &[])?;
assert_eq!(output, SessionOutput::Plain);
let payload = session.encrypt(b"example secret")?;
let value = session.decrypt(&payload.parameters, &payload.value)?;
assert_eq!(value.as_slice(), b"example secret");
# Ok::<(), secret_service_protocol::ProtocolError>(())
```

The host supplies the D-Bus adapter, authenticates callers, binds sessions to
their owners, and enforces access and lifecycle policy. Plain sessions transmit
unencrypted values. The DH/AES-CBC algorithm exists for Secret Service
interoperability and does not authenticate payloads; it is not a general-purpose
secure channel.

Licensed under Apache-2.0.
