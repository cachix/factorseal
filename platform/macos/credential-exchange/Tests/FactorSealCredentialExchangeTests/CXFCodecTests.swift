import Foundation
import Testing
@testable import FactorSealCredentialExchange

struct CXFCodecTests {
    private func fixture() throws -> [String: Any] {
        let url = try #require(Bundle.module.url(
            forResource: "login-totp", withExtension: "json", subdirectory: "Fixtures"
        ))
        return try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    @Test func appleSDKPreservesPasswordsNotesTOTPAndDates() throws {
        let source = try fixture()
        let bytes = try JSONSerialization.data(withJSONObject: source)
        let decoded = try CXFCodec.decode(bytes)
        let output = try CXFCodec.encode(decoded)
        let encoded = try JSONSerialization.jsonObject(with: output)
        #expect(CXFCodec.preserves(source: source, encoded: encoded))
        // Only this bundled synthetic fixture is written, never OS-delivered data.
        if let path = ProcessInfo.processInfo.environment["FACTORSEAL_TEST_APPLE_CXF_OUTPUT"] {
            try output.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
    }

    @Test func futureHeaderDataBlocksExportBeforeSystemPicker() throws {
        var source = try fixture()
        source["future"] = "retain me"
        let bytes = try JSONSerialization.data(withJSONObject: source)
        #expect(throws: CXFCodec.Failure.sdkWouldDiscardData) { try CXFCodec.decode(bytes) }
    }

    @Test func lossDetectionChecksNestedValuesAndArrayLengths() {
        #expect(!CXFCodec.preserves(source: ["credentials": [["secret": "original"]]], encoded: ["credentials": [["secret": "changed"]]]))
        #expect(!CXFCodec.preserves(source: ["a", "b"], encoded: ["a"]))
        #expect(CXFCodec.preserves(source: ["a": 1], encoded: ["a": 1, "default": false]))
    }

    @Test func futureAccountDataCannotBeSilentlyDiscarded() throws {
        var source = try fixture()
        var accounts = try #require(source["accounts"] as? [[String: Any]])
        accounts[0]["futureSyntheticProperty"] = "must survive"
        source["accounts"] = accounts
        let bytes = try JSONSerialization.data(withJSONObject: source)
        #expect(throws: (any Error).self) { try CXFCodec.decode(bytes) }
    }

    @Test func unsupportedVersionsAreRejected() throws {
        var source = try fixture()
        source["version"] = ["major": 2, "minor": 0]
        let bytes = try JSONSerialization.data(withJSONObject: source)
        #expect(throws: CXFCodec.Failure.unsupportedVersion) { try CXFCodec.decode(bytes) }
    }
}
