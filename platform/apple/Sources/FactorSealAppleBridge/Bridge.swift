import AppKit
import AuthenticationServices
import FactorSealCredentialExchange
import Foundation

// C ABI: data is borrowed only during the callback; Rust copies it into a
// bounded, zeroizing buffer. No credentials cross a file, argument, or URL.
public typealias ExchangeCallback = @convention(c) (UInt32, UnsafePointer<UInt8>?, Int) -> Void

@MainActor
protocol ExchangeTransport {
    func receive(_ activity: NSUserActivity) async throws -> Data
    func export(cxf: Data, anchor: NSWindow, extensionIdentifier: String) async throws
}

extension CredentialExchange: ExchangeTransport {}

@MainActor
final class Bridge: NSObject, NSApplicationDelegate {
    static var installed: Bridge?
    // Immutable retained reference. NSObject's nonisolated selector queries
    // only inspect/return this target; actual AppKit delegate calls remain on
    // the main actor. No mutable exchange state is exposed through it.
    nonisolated(unsafe) let original: any NSApplicationDelegate
    let callback: (UInt32, Data) -> Void
    let exchange: any ExchangeTransport
    var unlocked = false
    var busy = false
    var pending: NSUserActivity?
    var generation: UInt64 = 0
    var operation: Task<Void, Never>?

    init(original: any NSApplicationDelegate, exchange: any ExchangeTransport = CredentialExchange(),
         callback: @escaping (UInt32, Data) -> Void) {
        self.original = original
        self.exchange = exchange
        self.callback = callback
    }

    // Preserve GPUI's delegate behavior for every unrelated AppKit event.
    override nonisolated func responds(to selector: Selector!) -> Bool {
        super.responds(to: selector) || original.responds(to: selector)
    }

    override nonisolated func forwardingTarget(for selector: Selector!) -> Any? {
        original.responds(to: selector) ? original : super.forwardingTarget(for: selector)
    }

    func emit(_ kind: UInt32, _ data: Data = Data()) {
        callback(kind, data)
    }

    func application(_ application: NSApplication, continue activity: NSUserActivity,
                     restorationHandler: @escaping ([any NSUserActivityRestoring]) -> Void) -> Bool {
        guard activity.activityType == ASCredentialExchangeActivity else {
            return original.application?(application, continue: activity, restorationHandler: restorationHandler) ?? false
        }
        guard !busy, activity.userInfo?[ASCredentialImportToken] is UUID else { return false }
        busy = true
        pending = activity
        let epoch = generation
        operation = Task {
            try? await Task.sleep(for: .seconds(300))
            if generation == epoch, pending != nil, !Task.isCancelled {
                finish()
                emit(3)
            }
        }
        emit(5) // Open the app; Rust prompts for unlock before fetching data.
        receiveIfUnlocked()
        return true
    }

    func receiveIfUnlocked() {
        guard unlocked, let activity = pending else { return }
        pending = nil
        operation?.cancel()
        let epoch = generation
        operation = Task {
            do {
                let data = try await exchange.receive(activity)
                guard generation == epoch, unlocked, !Task.isCancelled else { return }
                emit(1, data) // Remain busy through Rust's preview and commit.
            } catch {
                if generation == epoch { emit(4) }
            }
        }
    }

    func setUnlocked(_ value: Bool) {
        if unlocked && !value && busy {
            finish()
            emit(3)
        }
        unlocked = value
        receiveIfUnlocked()
    }

    func finish() {
        generation &+= 1
        operation?.cancel()
        operation = nil
        pending = nil
        busy = false
    }

    func export(_ data: Data) -> Bool {
        guard unlocked, !busy, let anchor = NSApplication.shared.keyWindow,
              let identifier = Bundle.main.bundleIdentifier else { return false }
        busy = true
        let epoch = generation
        operation = Task {
            do {
                let projection = try SystemExport(data)
                if projection.omittedExtensions > 0 {
                    let alert = NSAlert()
                    alert.messageText = "Review system transfer"
                    alert.informativeText = "Apple's transfer format will omit FactorSeal-specific organization and field metadata (including folder, archived state, item kind, and field settings). Credential values remain checked for preservation. Use an encrypted CXF file to retain all metadata."
                    alert.addButton(withTitle: "Continue")
                    alert.addButton(withTitle: "Cancel")
                    guard await alert.beginSheetModal(for: anchor) == .alertFirstButtonReturn else {
                        if generation == epoch { emit(3) }
                        return
                    }
                }
                guard generation == epoch, unlocked, !Task.isCancelled else { return }
                try await exchange.export(cxf: projection.data, anchor: anchor,
                                          extensionIdentifier: identifier + ".credentials")
                if generation == epoch { emit(2) }
            } catch is CancellationError {
                if generation == epoch { emit(3) }
            } catch {
                if generation == epoch { emit(4) }
            }
        }
        return true
    }
}

@_cdecl("factorseal_apple_install")
@MainActor
public func install(_ callback: @escaping ExchangeCallback) -> Bool {
    guard Thread.isMainThread, Bridge.installed == nil,
          Bundle.main.object(forInfoDictionaryKey: "FactorSealExperimentalCredentialExchange") as? Bool == true,
          let original = NSApplication.shared.delegate else { return false }
    let bridge = Bridge(original: original) { kind, data in
        data.withUnsafeBytes { callback(kind, $0.bindMemory(to: UInt8.self).baseAddress, data.count) }
    }
    Bridge.installed = bridge
    NSApplication.shared.delegate = bridge
    return true
}

@_cdecl("factorseal_apple_set_unlocked")
@MainActor
public func setUnlocked(_ unlocked: Bool) { Bridge.installed?.setUnlocked(unlocked) }

@_cdecl("factorseal_apple_finish")
@MainActor
public func finish() { Bridge.installed?.finish() }

@_cdecl("factorseal_apple_export")
@MainActor
public func export(_ bytes: UnsafePointer<UInt8>?, _ count: Int) -> Bool {
    guard let bytes, count > 0, count <= 128 * 1024 * 1024 else { return false }
    return Bridge.installed?.export(Data(bytes: bytes, count: count)) ?? false
}
