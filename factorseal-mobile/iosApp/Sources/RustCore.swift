import FactorSealCore
import FactorSealKit
import Foundation

final class RustCore: NSObject, CoreBridge {
    func call(request: String) -> String {
        let bytes = Array(request.utf8)
        let response = bytes.withUnsafeBufferPointer { factorseal_call($0.baseAddress, $0.count) }
        defer { factorseal_free(response) }
        return String(decoding: UnsafeBufferPointer(start: response.data, count: response.length), as: UTF8.self)
    }

    func sealVault() {
        factorseal_seal()
    }
}
