import CryptoKit
import Foundation
import LocalAuthentication
import Security

// Fixed-size, caller-owned buffers form the complete FFI surface. No Swift
// objects, exceptions, strings, or ownership transfers cross into Rust.
private enum BridgeError: Error { case invalidInput }
private let unsupported: Int32 = 1
private let invalidInput: Int32 = 2
private let operationFailed: Int32 = 3
private let maxInput = 1024 * 1024
private let maxReference = 32768

@available(macOS 26.0, *)
private func accessControl(_ biometric: Bool) throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if biometric { flags.insert(.biometryCurrentSet) }
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error
    ) else {
        if let error { throw error.takeRetainedValue() }
        throw BridgeError.invalidInput
    }
    return access
}

private func pack(_ first: Data, _ second: Data) throws -> Data {
    guard !first.isEmpty, first.count <= maxReference else { throw BridgeError.invalidInput }
    var length = UInt32(first.count).bigEndian
    var result = withUnsafeBytes(of: &length) { Data($0) }
    result.append(first)
    result.append(second)
    return result
}

@available(macOS 26.0, *)
private func perform(_ operation: UInt32, _ first: Data, _ second: Data, _ biometric: Bool) throws -> Data {
    switch operation {
    case 1:
        let key = try SecureEnclave.MLDSA65.PrivateKey(accessControl: accessControl(biometric))
        return try pack(key.dataRepresentation, key.publicKey.rawRepresentation)
    case 2:
        let key = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: first)
        return key.publicKey.rawRepresentation
    case 3:
        let key = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: first)
        return try key.signature(for: second)
    case 4:
        let key = try SecureEnclave.MLKEM768.PrivateKey(accessControl: accessControl(biometric))
        return try pack(key.dataRepresentation, key.publicKey.rawRepresentation)
    case 5:
        let key = try MLKEM768.PublicKey(rawRepresentation: first)
        let encapsulation = try key.encapsulate()
        return try pack(encapsulation.encapsulated, encapsulation.sharedSecret.withUnsafeBytes { Data($0) })
    case 6:
        let key = try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: first)
        return try key.decapsulate(second).withUnsafeBytes { Data($0) }
    default:
        throw BridgeError.invalidInput
    }
}

@_cdecl("factorseal_apple_pq_available")
public func factorsealApplePQAvailable() -> Int32 {
    if #available(macOS 26.0, *) { return SecureEnclave.isAvailable ? 0 : unsupported }
    return unsupported
}

@_cdecl("factorseal_apple_pq_call")
public func factorsealApplePQCall(
    _ operation: UInt32,
    _ first: UnsafePointer<UInt8>?, _ firstLength: Int,
    _ second: UnsafePointer<UInt8>?, _ secondLength: Int,
    _ biometric: UInt32,
    _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int,
    _ outputLength: UnsafeMutablePointer<Int>?
) -> Int32 {
    guard let output, let outputLength,
          firstLength >= 0, firstLength <= maxInput,
          secondLength >= 0, secondLength <= maxInput,
          capacity > 0, capacity <= maxInput,
          firstLength == 0 || first != nil,
          secondLength == 0 || second != nil,
          biometric <= 1 else { return invalidInput }
    outputLength.pointee = 0
    guard #available(macOS 26.0, *), SecureEnclave.isAvailable else { return unsupported }
    do {
        var input1 = firstLength == 0 ? Data() : Data(bytes: first!, count: firstLength)
        var input2 = secondLength == 0 ? Data() : Data(bytes: second!, count: secondLength)
        defer {
            input1.resetBytes(in: input1.startIndex..<input1.endIndex)
            input2.resetBytes(in: input2.startIndex..<input2.endIndex)
        }
        var result = try perform(operation, input1, input2, biometric == 1)
        defer { result.resetBytes(in: result.startIndex..<result.endIndex) }
        guard result.count <= capacity else { return invalidInput }
        result.copyBytes(to: output, count: result.count)
        outputLength.pointee = result.count
        return 0
    } catch let error as NSError {
        // Preserve native authorization errors without exposing error strings
        // or operation data. Positive bridge errors occupy a separate range.
        if error.domain == NSOSStatusErrorDomain, error.code < 0,
           let code = Int32(exactly: error.code) { return code }
        return operationFailed
    }
}
