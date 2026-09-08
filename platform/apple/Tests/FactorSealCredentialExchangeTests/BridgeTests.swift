import AppKit
import AuthenticationServices
import Testing
@testable import FactorSealAppleBridge

@MainActor
struct BridgeTests {
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
        let bridge = Bridge(original: original, callback: { _, _, _ in })
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
        let bridge = Bridge(original: original, callback: { _, _, _ in })
        let activity = NSUserActivity(activityType: "dev.factorseal.synthetic-unrelated")
        #expect(bridge.application(NSApplication.shared, continue: activity, restorationHandler: { _ in }))
        #expect(original.received)
        #expect(!bridge.busy)
    }

    @Test func invalidImportActivityDoesNotStartAnOperation() {
        let bridge = Bridge(original: Original(), callback: { _, _, _ in })
        let activity = NSUserActivity(activityType: ASCredentialExchangeActivity)
        activity.userInfo = [ASCredentialImportToken: "not a UUID"]
        #expect(!bridge.application(NSApplication.shared, continue: activity, restorationHandler: { _ in }))
        #expect(!bridge.busy)
        #expect(bridge.pending == nil)
    }
}
