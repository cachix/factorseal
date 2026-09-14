# network-manager-protocol

Transport-independent NetworkManager secret-agent building blocks, following
the separation used by `secret-service-protocol`. This crate supplies the
interface names and paths, public flags, request arguments, D-Bus error names,
and personal/enterprise Wi-Fi secret validation and reply construction. Generic settings
dictionaries preserve the host's variant types, including non-string values.

```rust
use network_manager_protocol::{SecretFlags, WifiPsk};
use zeroize::Zeroizing;

let password = WifiPsk::new(
    "wpa-psk",
    Zeroizing::new("example-password".to_owned()),
)?;
assert!(SecretFlags::AGENT_OWNED.agent_may_save());
let reply = password.to_reply(|value| Zeroizing::new(value.to_owned()));
assert_eq!(reply["802-11-wireless-security"]["psk"].as_str(), "example-password");
# Ok::<(), network_manager_protocol::ProtocolError>(())
```

The example uses zeroizing strings as stand-ins for D-Bus string variants.
Passwords are wiped on drop and their `Debug` output is redacted; copies made
by a host or its D-Bus library require their own lifetime management.

A runtime adapter must:

- Export `GetSecrets`, `CancelGetSecrets`, `SaveSecrets`, and `DeleteSecrets`
  on the system bus and register with NetworkManager's `AgentManager`.
- Authenticate calls against NetworkManager's current unique bus owner and
  re-register when the daemon restarts.
- Decode and validate connection settings and object paths. Use the connection
  UUID, setting, and secret property as storage identity. Match cancellation
  against both fields of `RequestKey` and cancel all matching pending requests.
- Respect interaction flags. `REQUEST_NEW` implies interaction and disallows
  satisfying the request with an existing stored password. Hints are advisory.
- Persist only agent-owned secrets that permit saving. Secrets obtained or
  updated by the agent itself must be saved directly; a subsequent `SaveSecrets`
  call is not guaranteed. Delete requests carry connection metadata, not secrets.

Set `802-11-wireless-security.psk-flags=1` in a connection to delegate password
storage to a secret agent. This crate does not change profiles, register an
agent, implement a storage backend, or connect Factorseal to NetworkManager.
Personal Wi-Fi helpers support `wpa-psk` and `sae`. `EapSecrets` builds `802-1x`
replies for enterprise Wi-Fi (`wpa-eap`, `wpa-eap-suite-b-192`) and wired 802.1X:

- EAP passwords for authentication such as PEAP and TTLS, including arbitrary
  `password-raw` bytes. When both password forms are supplied, NetworkManager
  prefers the text `password`.
- Outer and phase-two private-key passwords for certificate authentication.
- EAP PINs and outer/phase-two CA and client-certificate token passwords.

Insert an `EapSecretProperty` and an `EapSecretValue::Text` or `Bytes` into an
`EapSecrets::default()` collection. Only `PasswordRaw` accepts bytes; all other
properties accept strings without embedded NULs. `to_reply` takes separate
string and byte-array variant constructors, and returns `NoSecrets` for an
empty collection. Empty values are distinct from absent properties. Secret
buffers are zeroized on replacement, rejection, and drop; debug output is
redacted for individual values and collections.

Each property's `flags_name()` identifies its independent persistence flags;
for example, use `802-1x.password-flags=1` for an agent-owned EAP password.
The host must apply those flags per secret, including `NOT_SAVED` for secrets
that must not persist. It selects credentials for the configured EAP method
and handles connection identity, certificate/key configuration, and server
certificate verification. The crate validates secret wire representations;
it does not validate a complete EAP profile or perform EAP authentication.
VPN secret interpretation remains outside these helpers.

References: [SecretAgent API](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.SecretAgent.html),
[AgentManager API](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.AgentManager.html),
[secret flags](https://networkmanager.dev/docs/api/latest/secrets-flags.html),
[Wi-Fi security](https://networkmanager.dev/docs/api/latest/settings-802-11-wireless-security.html),
[802.1X settings](https://networkmanager.dev/docs/api/latest/settings-802-1x.html).

Checks:

```sh
devenv shell -- cargo test -p network-manager-protocol
devenv shell -- cargo clippy -p network-manager-protocol --all-targets -- -D warnings
devenv shell -- cargo fmt --all -- --check
```
