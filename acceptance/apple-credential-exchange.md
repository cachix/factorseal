# Apple Passwords credential exchange acceptance

**Current status: experimental extension and desktop integration; live acceptance NOT RUN.**
Build with `FACTORSEAL_APPLE_EXCHANGE=1` and both app/extension provisioning
profiles as described in [the Apple adapter guide](../platform/apple/README.md).
The SDK and package CI checks do not exercise the live system picker.
Do not record a file transfer or SDK test as a passing system-transfer result.

## Setup

Use a macOS 26+ interactive desktop session with Apple Passwords and a dedicated
test vault. Install a FactorSeal build containing the credential-provider
extension, app and extension provisioning profiles, and required credential
exchange capabilities. Record the commit, app version, macOS version, selected
Xcode version, app and extension bundle identifiers, and signing verification
result. Run the SDK test runner first and retain its logs.

Use only synthetic test credentials. In Apple Passwords, create a login for
`https://example.test` with username `alice`, password `synthetic-password`,
note `Synthetic note`, and verification-code seed `JBSWY3DPEHPK3PXP` (SHA-1,
six digits, 30 seconds). These values are public fixtures, not usable accounts.

## Cases

| Case | Procedure | Passing result |
| --- | --- | --- |
| Import | Select the synthetic login in Apple Passwords and initiate system transfer to FactorSeal. Review and accept the FactorSeal preview. | One usable login arrives with the original username, password, website, note, and TOTP parameters. Compare displayed codes within the same time interval. The source login remains in Apple Passwords. |
| Edit and return | Change the password and note in FactorSeal, then export that item using the system picker to Apple Passwords. | The receiving item contains the edited values and working TOTP. Old values are not revived from retained source metadata. Record the destination's duplicate-handling behavior. |
| Picker cancellation | Cancel the system export picker before selecting a destination. | No destination changes and no plaintext files. FactorSeal can start another transfer. |
| Preview cancellation | Receive an OS transfer, then cancel FactorSeal's import preview. | No FactorSeal vault records are written. |
| Locked vault | Receive a transfer while FactorSeal is sealed. | No records become readable or writable until the authorized unlock flow completes. Canceling unlock leaves the vault unchanged. |
| Interruption | With several synthetic items, terminate FactorSeal after some imports complete. Restart and retry while keeping existing items. | Completed items remain; retry introduces no duplicates and imports remaining items. A last write whose reply was lost is retained. |
| Unsupported data | Try a credential or extension the SDK/core cannot preserve, and a CXF attachment reference. | Transfer is rejected or explicitly reports the unsupported data before any affected import is accepted. No silent loss. |

The synthetic fixture verifies data transfer, not successful website login.
Before release acceptance, also use a controlled test website with a real test
account to verify login and TOTP after migration. Passkey authentication requires
its own provider/signing implementation and separate acceptance; retaining a
passkey in source metadata is not a pass.

## Evidence

Record each case as PASS, FAIL, or NOT RUN with a short observation. Include the
SDK test results and build identifiers. Overall system-transfer acceptance is
PASS only when every applicable case has run successfully on the signed build.
Keep the dedicated source vault until verification finishes. Cleanup is limited
to the synthetic items and test vault created for this run.
