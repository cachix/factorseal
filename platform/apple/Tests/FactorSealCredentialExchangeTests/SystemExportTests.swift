import Foundation
import Testing
@testable import FactorSealCredentialExchange

struct SystemExportTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["FACTORSEAL_TEST_APPLE_NATIVE_CXF"] != nil))
    func actualRustExportRetainsCredentialDataThroughAppleSDK() throws {
        let input = try #require(ProcessInfo.processInfo.environment["FACTORSEAL_TEST_APPLE_NATIVE_CXF"])
        let output = try #require(ProcessInfo.processInfo.environment["FACTORSEAL_TEST_APPLE_NATIVE_OUTPUT"])
        let source = try Data(contentsOf: URL(fileURLWithPath: input))
        let projection = try SystemExport(source)
        #expect(projection.omittedExtensions > 0)
        let encoded = try CXFCodec.encode(CXFCodec.decode(projection.data))
        #expect(CXFCodec.preserves(
            source: try JSONSerialization.jsonObject(with: projection.data),
            encoded: try JSONSerialization.jsonObject(with: encoded)
        ))
        try encoded.write(to: URL(fileURLWithPath: output), options: .atomic)
    }

    func fixture() throws -> [String: Any] {
        let url = try #require(Bundle.module.url(forResource: "login-totp", withExtension: "json", subdirectory: "Fixtures"))
        return try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    @Test func onlyKnownFactorSealMetadataCanBeOmitted() throws {
        let source = try fixture()
        var annotated = source
        var accounts = try #require(source["accounts"] as? [[String: Any]])
        var items = try #require(accounts[0]["items"] as? [[String: Any]])
        items[0]["extensions"] = [["name": "org.factorseal.item", "version": 1, "folder": "Synthetic folder"]]
        accounts[0]["items"] = items
        annotated["accounts"] = accounts
        let projection = try SystemExport(JSONSerialization.data(withJSONObject: annotated))
        #expect(projection.omittedExtensions == 1)
        #expect(CXFCodec.preserves(source: source, encoded: try JSONSerialization.jsonObject(with: projection.data)))
        // Future versions must not inherit permission to omit unknown metadata.
        items[0]["extensions"] = [["name": "org.factorseal.item", "version": 99, "future": "preserve"]]
        accounts[0]["items"] = items
        annotated["accounts"] = accounts
        #expect(throws: (any Error).self) { try SystemExport(JSONSerialization.data(withJSONObject: annotated)) }
        items[0]["futureCredentialProperty"] = "preserve"
        items[0].removeValue(forKey: "extensions")
        accounts[0]["items"] = items
        annotated["accounts"] = accounts
        #expect(throws: (any Error).self) { try SystemExport(JSONSerialization.data(withJSONObject: annotated)) }
    }
}
