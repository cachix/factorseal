# Apple credential exchange adapter

This Swift package implements the macOS 26 AuthenticationServices transport,
the CXF Account Codable boundary, and an in-memory C ABI used by the GPUI desktop.
An **opt-in experimental app bundle** includes a credential-provider extension.
Ordinary builds keep system transfer disabled. Live Apple Passwords acceptance
has not passed; password AutoFill and passkey signing are not implemented.

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
The runner also generates a native FactorSeal login with the Rust exporter,
passes its reviewed metadata projection through Apple's SDK, and checks the
result with both Rust readers. Additional tests cover unsupported versions,
metadata loss, locked imports, cancellation, and late SDK replies after sealing. For only the Swift tests, run `swift test --package-path platform/apple`.

The **Apple credential exchange** GitHub Actions workflow runs this command on
`macos-26` for relevant pull requests and pushes to `main`; it also supports
manual dispatch. Logs, toolchain information, and the synthetic JSON output are
saved under `platform/apple/.build/credential-exchange-results/run.*` and
uploaded as `apple-credential-exchange-results` for 14 days in CI. A successful
job proves SDK and schema compatibility; it does not exercise Apple's picker,
code signing, Secure Enclave policy, or a live password manager.

## Experimental desktop bundle

On a macOS 26 CI runner or development machine:

```sh
FACTORSEAL_APPLE_EXCHANGE=1 sh packaging/build-unix.sh macos
```

The bundle launches `factorseal-desktop`, includes the sibling CLI vault worker,
embeds `libFactorSealAppleBridge.dylib` under `Contents/Frameworks`, and contains
`FactorSealCredentialProvider.appex` under `Contents/PlugIns`. This opt-in bundle
requires macOS 26. Ordinary CLI packages retain their macOS 11 deployment target.
`FACTORSEAL_BUILD_PROFILE=dev` builds the faster development package used in CI.

The experimental packaging CI job verifies nested signatures, capabilities,
version and bundle identifiers, native bridge symbols, and loading the real Rust
executable with its Swift library. Its ad-hoc signature is for packaging checks;
it cannot establish acceptance of live system transfer.

For a Team-signed experimental package, supply:

- `FACTORSEAL_MACOS_SIGNING_IDENTITY`: the selected signing identity.
- `FACTORSEAL_MACOS_PROVISIONING_PROFILE`: the containing app profile for `dev.factorseal`.
- `FACTORSEAL_MACOS_EXTENSION_PROVISIONING_PROFILE`: the extension profile for `dev.factorseal.credentials`.

Both profiles must authorize the credential-provider entitlement and the selected
certificate, belong to the same team, and use the same application identifier
prefix. The extension has its own application identity and sandbox entitlement;
it receives no vault Keychain access group. The containing app and its CLI worker
retain the app's protected Keychain access. Profiles are validated before signing
nested bundles, followed by the outer app.

## Transfer behavior

The Swift bridge forwards unrelated AppKit delegate messages to GPUI. A system
import activity opens the desktop and retains one import token while awaiting
unlock, for at most five minutes. No credential data is fetched until the vault
is unsealed. Received CXF crosses a synchronous borrowed-buffer C callback into a
bounded Rust channel and zeroizing buffer, then follows the prepared-import
validation and review flow. Cancelled previews write nothing. Sealing the vault
invalidates an in-flight operation; the vault service also enforces authorization
when a commit reaches it. Existing items are kept unless replacement was selected.

In **Transfer credentials**, **Choose destination app…** exports Personal records
through Apple's picker. A separate confirmation is required before omitting known
FactorSeal item/field extensions (organization, item kind, archived state, and
field settings). All remaining source data must survive the SDK mapping, or
export stops before the picker. Future extension versions receive no omission
exception. Encrypted CXF file export continues to retain the complete structure.

The extension advertises credential exchange only; its AutoFill request handler
returns a failure instead of pretending passwords or passkeys are supported.
There is no new credential file, URL scheme, shared vault directory, or secret
command-line argument in this bridge.

The [live Apple Passwords acceptance procedure](../../acceptance/apple-credential-exchange.md)
is still required on a properly provisioned build before enabling this in ordinary
packages. CI does not prove picker discovery, live transfer, or successful website
login. It does not provide passkey authentication or attachment transport.

Swift and AuthenticationServices may copy `Data` internally; this package makes
no claim of complete memory erasure or post-quantum security for Apple's system
transport. The separate hybrid age transport has its own security properties.

References: [Apple export manager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager),
[Apple import manager](https://developer.apple.com/documentation/authenticationservices/ascredentialimportmanager),
[CXF Account decoding](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
