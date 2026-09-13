import AppKit
import AuthenticationServices
import Foundation

/// In-memory system transport. The containing app must have a signed credential
/// provider extension and receive ASCredentialExchangeActivity activities.
@MainActor
public final class CredentialExchange {
    public enum Failure: Error {
        case exchangeInProgress
        case invalidImportActivity
        case unsupportedVersion
    }

    private var exchanging = false

    public init() {}

    public func export(cxf: Data, anchor: NSWindow, extensionIdentifier: String) async throws {
        guard !exchanging else { throw Failure.exchangeInProgress }
        exchanging = true
        defer { exchanging = false }
        let credentials = try CXFCodec.decode(cxf)
        let manager = ASCredentialExportManager(presentationAnchor: anchor)
        let options = try await manager.requestExport(for: extensionIdentifier)
        guard options.formatVersion == .v1 else { throw Failure.unsupportedVersion }
        try await manager.exportCredentials(credentials)
    }

    /// Returns authenticated OS-delivered CXF for Rust validation and an import
    /// preview. Receiving a token never commits records or removes source data.
    public func receive(_ activity: NSUserActivity) async throws -> Data {
        guard !exchanging else { throw Failure.exchangeInProgress }
        guard activity.activityType == ASCredentialExchangeActivity,
              let token = activity.userInfo?[ASCredentialImportToken] as? UUID
        else { throw Failure.invalidImportActivity }
        exchanging = true
        defer { exchanging = false }
        let credentials = try await ASCredentialImportManager().importCredentials(token: token)
        return try CXFCodec.encode(credentials)
    }
}
