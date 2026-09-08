# Apple credential exchange adapter

This Swift package implements the macOS 26 AuthenticationServices transport and
the documented CXF Account Codable boundary. It is **not connected to the GPUI
application or included in the signed app package yet**. It does not make
FactorSeal appear in Apple's transfer picker or provide AutoFill/passkey signing.

Run from the repository root on macOS 26 with full Xcode 26 or newer and the
repository's Rust toolchain:

```sh
bash scripts/test-apple-exchange.sh
```

If multiple Xcode versions are installed, select one for this invocation:

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer bash scripts/test-apple-exchange.sh
```

The runner checks the operating system, Xcode, and SDK versions. It then runs
Swift tests and passes Apple's encoded output to FactorSeal's Rust importer,
the independent CXF reader, and FactorSeal's re-exporter. It fails if Swift does
not produce that output, so the interoperability check cannot silently skip.
The bundled fixture contains synthetic passwords, notes, TOTP, URLs, account
and item identities, and timestamps. No vault or signing credentials are used.
Additional tests cover unsupported versions and metadata that the SDK would
discard. For only the Swift tests, run `swift test --package-path platform/apple`.

The **Apple credential exchange** GitHub Actions workflow runs this command on
`macos-26` for relevant pull requests and pushes to `main`; it also supports
manual dispatch. Logs, toolchain information, and the synthetic JSON output are
saved under `platform/apple/.build/credential-exchange-results/run.*` and
uploaded as `apple-credential-exchange-results` for 14 days in CI. A successful
job proves SDK and schema compatibility; it does not exercise Apple's picker,
code signing, Secure Enclave policy, or a live password manager.

Export stops if Apple's typed representation discards supplied
properties, including extensions. FactorSeal vendor extensions have no implicit
exception: the application needs an explicit preview of any unsupported data
before a narrower system export can be offered. Use encrypted CXF files when
the complete source structure is required.

The [live Apple Passwords acceptance procedure](../../acceptance/apple-credential-exchange.md)
covers the later signed-app test. Host integration still requires:

1. A credential-provider extension target with the AutoFill provider entitlement,
   `SupportsCredentialExchange = YES`, and `SupportedCredentialExchangeVersions`
   containing `1.0` in `ASCredentialProviderExtensionCapabilities`.
2. An app entitlement/profile and a separate extension entitlement/profile,
   matching bundle identifiers, and proper nested extension signing.
3. `NSUserActivityTypes = [ASCredentialExchangeActivityType]` in the containing
   app, forwarding activities to `CredentialExchange.receive`.
4. A Rust bridge using in-memory CXF, an import preview, and vault commits after
   validation. Do not pass secrets in arguments, logs, clipboard, or temp files.
5. Live Apple Passwords → FactorSeal → Apple Passwords acceptance with login and
   TOTP edits, cancellation, locked vaults, and process interruption. Only then
   enable the feature in the application.

Swift and AuthenticationServices may copy `Data` internally; this package makes
no claim of complete memory erasure or post-quantum security for Apple's system
transport. The separate hybrid age transport has its own security properties.

References: [Apple export manager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager),
[Apple import manager](https://developer.apple.com/documentation/authenticationservices/ascredentialimportmanager),
[CXF Account decoding](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
