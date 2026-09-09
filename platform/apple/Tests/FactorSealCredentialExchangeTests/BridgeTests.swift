import AppKit
import AuthenticationServices
import Testing
@testable import FactorSealAppleBridge

@MainActor
struct BridgeTests {
    final class SuspendedTransport: ExchangeTransport {
        var continuation: CheckedContinuation<Data, any Error>?
        var receives = 0
        func receive(_ activity: NSUserActivity) async throws -> Data {
            receives += 1
            return try await withCheckedThrowingContinuation { continuation = $0 }
        }
        func export(cxf: Data, anchor: NSWindow, extensionIdentifier: String) async throws {
            throw CancellationError()
        }
    }

    @Test(arguments: [false, true])
    func importWaitsForUnlockAndRejectsLateCompletion(sealDuringReceipt: Bool) async throws {
        let transport = SuspendedTransport()
        var events: [UInt32] = []
        let bridge = Bridge(original: Original(), exchange: transport) { kind, _ in events.append(kind) }
        let activity = NSUserActivity(activityType: ASCredentialExchangeActivity)
        activity.userInfo = [ASCredentialImportToken: UUID()]
        #expect(bridge.application(NSApplication.shared, continue: activity, restorationHandler: { _ in }))
        #expect(transport.receives == 0)
        #expect(events == [5])
        bridge.setUnlocked(true)
        for _ in 0..<100 {
            if transport.continuation != nil { break }
            await Task.yield()
        }
        let continuation = try #require(transport.continuation)
        let operation = try #require(bridge.operation)
        if sealDuringReceipt { bridge.setUnlocked(false) }
        // Simulate an SDK operation completing despite task cancellation.
        continuation.resume(returning: Data("synthetic response".utf8))
        await operation.value
        #expect(events == (sealDuringReceipt ? [5, 3] : [5, 1]))
        #expect(bridge.busy == !sealDuringReceipt)
        bridge.finish()
        #expect(!bridge.busy)
        #expect(bridge.pending == nil)
    }

    final class Original: NSObject, NSApplicationDelegate {
        var received = false
        func application(_ application: NSApplication, continue activity: NSUserActivity,
                         restorationHandler: @escaping ([any NSUserActivityRestoring]) -> Void) -> Bool {
            received = true
            return true
        }
    }

    @Test func lockedImportRetainsOnlyOneTokenAndCancellationClearsIt() {
        let original = Original()
        let bridge = Bridge(original: original, callback: { _, _ in })
        let activity = NSUserActivity(activityType: ASCredentialExchangeActivity)
        activity.userInfo = [ASCredentialImportToken: UUID()]
        #expect(bridge.application(NSApplication.shared, continue: activity, restorationHandler: { _ in }))
        #expect(bridge.busy)
        #expect(bridge.pending === activity)
        #expect(!bridge.application(NSApplication.shared, continue: activity, restorationHandler: { _ in }))
        bridge.finish()
        #expect(!bridge.busy)
        #expect(bridge.pending == nil)
        #expect(bridge.operation == nil)
    }

    @Test func unrelatedActivitiesReachTheOriginalDelegate() {
        let original = Original()
        let bridge = Bridge(original: original, callback: { _, _ in })
        let activity = NSUserActivity(activityType: "dev.factorseal.synthetic-unrelated")
        #expect(bridge.application(NSApplication.shared, continue: activity, restorationHandler: { _ in }))
        #expect(original.received)
        #expect(!bridge.busy)
    }

    @Test func invalidImportActivityDoesNotStartAnOperation() {
        let bridge = Bridge(original: Original(), callback: { _, _ in })
        let activity = NSUserActivity(activityType: ASCredentialExchangeActivity)
        activity.userInfo = [ASCredentialImportToken: "not a UUID"]
        #expect(!bridge.application(NSApplication.shared, continue: activity, restorationHandler: { _ in }))
        #expect(!bridge.busy)
        #expect(bridge.pending == nil)
    }
}
