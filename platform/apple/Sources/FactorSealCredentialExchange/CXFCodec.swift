import AuthenticationServices
import Foundation

/// The SDK boundary only. Vault validation and commits belong to the Rust core.
public enum CXFCodec {
    public enum Failure: Error, Equatable {
        case invalidHeader
        case unsupportedVersion
        case payloadTooLarge
        case sdkWouldDiscardData
    }

    private static let maximumBytes = 128 * 1024 * 1024

    public static func decode(_ data: Data) throws -> ASExportedCredentialData {
        guard data.count <= maximumBytes else { throw Failure.payloadTooLarge }
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let version = root["version"] as? [String: Int],
              let accounts = root["accounts"] as? [[String: Any]],
              let relyingParty = root["exporterRpId"] as? String,
              let name = root["exporterDisplayName"] as? String,
              let timestamp = root["timestamp"] as? NSNumber,
              timestamp.doubleValue >= 0
        else { throw Failure.invalidHeader }
        guard version == ["major": 1, "minor": 0] else { throw Failure.unsupportedVersion }
        guard Set(root.keys) == Set(["version", "accounts", "exporterRpId", "exporterDisplayName", "timestamp"])
        else { throw Failure.sdkWouldDiscardData }

        // Apple documents the Account Codable mapping, including its date strategy.
        // Do not assume the wrapper's synthesized Codable representation is CXF.
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        let accountBytes = try JSONSerialization.data(withJSONObject: accounts)
        let decoded = try decoder.decode([ASImportableAccount].self, from: accountBytes)
        let encoded = try JSONSerialization.jsonObject(with: encoder.encode(decoded))
        // SDK types may omit extensions or future fields. Stop before opening
        // the picker if that would silently remove any supplied source data.
        guard preserves(source: accounts, encoded: encoded) else { throw Failure.sdkWouldDiscardData }
        return ASExportedCredentialData(
            accounts: decoded, formatVersion: .v1,
            exporterRelyingPartyIdentifier: relyingParty,
            exporterDisplayName: name,
            timestamp: Date(timeIntervalSince1970: timestamp.doubleValue)
        )
    }

    public static func encode(_ credentials: ASExportedCredentialData) throws -> Data {
        guard credentials.formatVersion == .v1 else { throw Failure.unsupportedVersion }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        let accounts = try JSONSerialization.jsonObject(with: encoder.encode(credentials.accounts))
        let root: [String: Any] = [
            "version": ["major": 1, "minor": 0],
            "exporterRpId": credentials.exporterRelyingPartyIdentifier,
            "exporterDisplayName": credentials.exporterDisplayName,
            "timestamp": credentials.timestamp.timeIntervalSince1970.rounded(.down),
            "accounts": accounts,
        ]
        let data = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        guard data.count <= maximumBytes else { throw Failure.payloadTooLarge }
        return data
    }

    // Optional SDK defaults may be added. Every value the caller supplied must
    // survive; errors never include field paths, titles, or credential contents.
    static func preserves(source: Any, encoded: Any) -> Bool {
        if let source = source as? [String: Any] {
            guard let encoded = encoded as? [String: Any] else { return false }
            return source.allSatisfy { key, value in
                guard let result = encoded[key] else { return value is NSNull }
                return preserves(source: value, encoded: result)
            }
        }
        if let source = source as? [Any] {
            guard let encoded = encoded as? [Any], source.count == encoded.count else { return false }
            return zip(source, encoded).allSatisfy { preserves(source: $0.0, encoded: $0.1) }
        }
        return (source as? NSObject)?.isEqual(encoded) == true
    }
}
