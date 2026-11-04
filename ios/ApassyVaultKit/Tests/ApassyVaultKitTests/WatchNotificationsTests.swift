import Foundation
import Testing
@testable import ApassyVaultKit

/// "Notifications on this watch" (push-gateway-v1 section 11): the watch registers its own push
/// handle only when the owner turns it on, and takes it away when it is turned off.
@MainActor
@Suite struct WatchNotificationsTests {
    @MainActor
    final class Permission: WatchPushPermission {
        var allowed = true
        var registered = 0
        var unregistered = 0
        let environment = PushEnvironment.production
        func requestAuthorization() async -> Bool { allowed }
        func registerForPushes() { registered += 1 }
        func unregisterForPushes() { unregistered += 1 }
    }

    /// Records the push calls; every other call of the watch is refused.
    actor Service: WatchService {
        private(set) var tokens: [(Data, PushEnvironment)] = []
        private(set) var clears = 0
        var failure: VaultError?

        func fail(with error: VaultError?) { failure = error }

        func pushTokenSet(token: Data, environment: PushEnvironment) async throws {
            if let failure { throw failure }
            tokens.append((token, environment))
        }

        func pushTokenClear() async throws { clears += 1 }

        func pushSummaryKeys() async throws -> [PushSummaryKey] {
            [PushSummaryKey(teamID: "t_7k2m5q4x3c", key: "K-iD_0Xo0XYWPOS-Iz7HiP6Cs2rdeAtf21jMtRLg-Zc")]
        }

        private func refused() -> VaultError { VaultError(.notAllowed, "synthetic") }
        func status(answerKey: Data?) async throws -> WatchStatus { throw refused() }
        func connectStart(link: String, name: String, answerKey: Data, passphrase: String) async throws
            -> WatchConnectInfo
        { throw refused() }
        func connectPoll() async throws -> WatchConnectInfo { throw refused() }
        func connectCancel() async throws {}
        func forget() async throws {}
        func select(vaultID: String) async throws {}
        func unlock(passphrase: String) async throws {}
        func lock() async throws {}
        func suspend() async throws {}
        func accessRequestsList() async throws -> AccessRequestsSnapshot { throw refused() }
        func accessRequestPrepare(_ request: RelayAccessRequest, choice: AccessChoice) async throws
            -> PreparedAccessAnswer
        { throw refused() }
        func accessRequestAnswer(
            _ request: RelayAccessRequest, choice: AccessChoice, prepared: PreparedAccessAnswer, signature: Data?
        ) async throws -> SentAccessAnswer { throw refused() }
        func accessRequestCancelPrepared() async {}
        func wait(timeout: Int) async throws -> Bool { false }
    }

    private let token = Data(repeating: 0xc3, count: 32)

    private func defaults() -> UserDefaults { UserDefaults(suiteName: "watch-notifications-\(UUID().uuidString)")! }

    @Test func itIsOffUntilTheOwnerTurnsItOn() async {
        let permission = Permission()
        let service = Service()
        let keys = MemoryPushSummaryKeyStore()
        let model = WatchNotificationsModel(service: service, permission: permission, keys: keys, defaults: defaults())
        #expect(!model.enabled)
        #expect(model.status == .off)
        // A token without the setting goes nowhere.
        await model.receiveToken(token)
        await model.refresh()
        #expect(await service.tokens.isEmpty)
        #expect(permission.registered == 0)
    }

    @Test func onRegistersSendsTheTokenAndKeepsTheSummaryKey() async {
        let permission = Permission()
        let service = Service()
        let keys = MemoryPushSummaryKeyStore()
        let store = defaults()
        let model = WatchNotificationsModel(service: service, permission: permission, keys: keys, defaults: store)
        await model.setEnabled(true)
        #expect(model.enabled)
        #expect(model.status == .registering)
        #expect(permission.registered == 1)
        await model.receiveToken(token)
        #expect(model.status == .on)
        let sent = await service.tokens
        #expect(sent.count == 1)
        #expect(sent.first?.0 == token)
        #expect(sent.first?.1 == .production)
        #expect(keys.teamIDs() == ["t_7k2m5q4x3c"])
        // A new launch keeps the setting and registers again.
        let again = WatchNotificationsModel(service: service, permission: permission, keys: keys, defaults: store)
        #expect(again.enabled)
        await again.refresh()
        #expect(permission.registered == 2)
    }

    @Test func offTakesTheHandleAndTheKeyAway() async {
        let permission = Permission()
        let service = Service()
        let keys = MemoryPushSummaryKeyStore()
        let model = WatchNotificationsModel(service: service, permission: permission, keys: keys, defaults: defaults())
        await model.setEnabled(true)
        await model.receiveToken(token)
        await model.setEnabled(false)
        #expect(!model.enabled)
        #expect(model.status == .off)
        #expect(await service.clears == 1)
        #expect(permission.unregistered == 1)
        #expect(keys.teamIDs().isEmpty)
    }

    @Test func aDeniedPermissionLeavesItOff() async {
        let permission = Permission()
        permission.allowed = false
        let model = WatchNotificationsModel(
            service: Service(), permission: permission, keys: MemoryPushSummaryKeyStore(), defaults: defaults())
        await model.setEnabled(true)
        #expect(!model.enabled)
        #expect(model.status == .denied)
        #expect(permission.registered == 0)
    }

    @Test func aLockedReplicaWaitsAndTheHostedRelaySaysSo() async {
        let permission = Permission()
        let service = Service()
        let model = WatchNotificationsModel(
            service: service, permission: permission, keys: MemoryPushSummaryKeyStore(), defaults: defaults())
        await model.setEnabled(true)
        await service.fail(with: VaultError(.locked, "Locked."))
        await model.receiveToken(token)
        #expect(model.status == .registering)
        await service.fail(with: nil)
        await model.refresh()
        #expect(model.status == .on)
        let message = "This relay sends no notifications. Questions show while Apassy is open."
        await service.fail(with: VaultError(.internal, message))
        await model.refresh()
        #expect(model.status == .failed(VaultError(.internal, message).localizedDescription))
    }
}
