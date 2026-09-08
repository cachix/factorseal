import AppKit
import AuthenticationServices

/// Credential exchange is handled by the containing app. This extension does
/// not advertise password or passkey AutoFill until those are implemented.
@objc(FactorSealCredentialProvider)
final class CredentialProvider: ASCredentialProviderViewController {
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        extensionContext.cancelRequest(withError: NSError(
            domain: ASExtensionErrorDomain, code: ASExtensionError.Code.failed.rawValue
        ))
    }
}
