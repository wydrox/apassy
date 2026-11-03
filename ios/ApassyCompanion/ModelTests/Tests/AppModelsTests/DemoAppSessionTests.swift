import ApassyCompanionKit
import ApassyVaultDemo
import ApassyVaultKit
import Foundation
import Synchronization
import Testing

@testable import AppModels

/// The app as the demo must not use it: every call but the pasteboard fails the test. A real
/// vault would call the core, the App Group defaults, the keychain, the AutoFill identity store,
/// and push through it.
@MainActor
private final class FailingWorld: AppWorld {
    private(set) var copies: [(value: String, secret: Bool, clearAfter: ClearAfter)] = []
    private(set) var calls: [String] = []

    private func fail(_ name: String) {
        calls.append(name)
        Issue.record("The demo called \(name) of the app.")
    }

    func copy(_ value: String, secret: Bool, clearAfter: ClearAfter) {
        copies.append((value, secret, clearAfter))
    }

    func makeCoreService(deviceName: String?) throws -> any VaultService {
        fail("makeCoreService")
        throw VaultError(.io, "No core in the demo.")
    }

    func sharedSettings() -> any SettingsStore {
        fail("sharedSettings")
        return MemorySettingsStore()
    }

    func keychainPassphraseStore() -> any PassphraseStore {
        fail("keychainPassphraseStore")
        return DemoPassphraseStore(confirm: { _ in false })
    }

    func keychainAnswerKeyStore() -> any AnswerKeyStore {
        fail("keychainAnswerKeyStore")
        return NoAnswerKeys()
    }

    func replaceIdentities(_ identities: IdentitySet, vaultID: String) async { fail("replaceIdentities") }

    func removeAllIdentities() async { fail("removeAllIdentities") }

    func pushPermission() -> any PushPermission {
        fail("pushPermission")
        return DemoPush(notAvailable: {})
    }

    func endFaceIDWindow() { fail("endFaceIDWindow") }
}

private struct NoAnswerKeys: AnswerKeyStore {
    func load(service: String) throws -> (any CompanionKeys)? { nil }
    func create(service: String) throws -> any CompanionKeys { SoftwareKeys() }
}

/// Counts calls from main-actor closures.
@MainActor
private final class Counter {
    var value = 0
}

/// The Face ID prompts of the demo: their reasons, and the answer.
private final class Prompts: Sendable {
    private let state = Mutex<(reasons: [String], allow: Bool)>(([], true))
    var reasons: [String] { state.withLock { $0.reasons } }
    func set(allow: Bool) { state.withLock { $0.allow = allow } }
    func confirm(_ reason: String) -> Bool {
        state.withLock { state in
            state.reasons.append(reason)
            return state.allow
        }
    }
}

/// The demo of the store build over the real models of the app: what it shows, the simulated
/// answers, that it uses nothing of the app but the pasteboard, and that leaving drops it.
@MainActor
@Suite(.serialized) struct DemoAppSessionTests {
    private func session(
        world: FailingWorld = FailingWorld(), prompts: Prompts = Prompts(), notAvailable: @escaping @MainActor () -> Void = {}
    ) async -> DemoAppSession {
        let demo = await DemoSession.open(confirm: { prompts.confirm($0) })
        return DemoAppSession(
            demo: demo, world: world, ownerCheck: ScriptedOwnerCheck(), confirm: { prompts.confirm($0) },
            canUseFaceID: { true }, notAvailable: notAvailable)
    }

    private func started(_ session: DemoAppSession) async {
        await session.vault.start()
        await session.questions.refresh()
        await session.questions.access.refresh()
    }

    // MARK: - What the demo shows

    @Test func theDemoOpensUnlockedWithItsSampleData() async throws {
        let world = FailingWorld()
        let demo = await session(world: world)
        await started(demo)
        #expect(demo.vault.isUnlocked)
        #expect(demo.vault.vault?.name == DemoVault.name)
        #expect(demo.vault.activeItems.contains { $0.hasTotp && !$0.websites.isEmpty })
        #expect(demo.vault.activeItems.contains { $0.hasPasskey })
        #expect(!demo.vault.folders.isEmpty)
        #expect(demo.questions.questions.contains { $0.qid == DemoVault.runQuestionID })
        #expect(demo.questions.access.requests.contains { $0.id == DemoVault.accessRequestID && $0.state == "open" })
        #expect(world.calls.isEmpty)
    }

    @Test func revealAndCopyUseFakeValuesWithTheNormalExpiry() async throws {
        let world = FailingWorld()
        let demo = await session(world: world)
        await started(demo)
        let shop = try #require(demo.vault.activeItems.first { $0.title == "Example Shop" })
        let detail = try await demo.vault.service.item(id: shop.id)
        let password = try #require(detail.fields.first { $0.role == .password })
        await demo.vault.copy(password, of: shop.title, itemID: shop.id)
        let copy = try #require(world.copies.last)
        #expect(copy.value.hasPrefix("synthetic-") && copy.secret)
        // The clipboard time of a new vault: one minute.
        #expect(copy.clearAfter == .oneMinute)
        #expect(world.calls.isEmpty)
    }

    @Test func findDuplicatesFindsThePlantedDuplicate() async throws {
        let demo = await session()
        await started(demo)
        let groups = try await demo.vault.service.duplicates()
        #expect(groups.contains { group in group.items.contains { $0.title == "Netflix (old)" } })
    }

    // MARK: - Simulated answers

    @Test func allowOnceAsksFaceIDWithTheReasonOfTheRequestAndSettlesLocally() async throws {
        let prompts = Prompts()
        let world = FailingWorld()
        let demo = await session(world: world, prompts: prompts)
        await started(demo)
        let request = try #require(demo.questions.access.requests.first { $0.id == DemoVault.accessRequestID })
        #expect(demo.questions.access.canAllow(request))
        await demo.questions.access.answer(request, choice: .allow_once)
        // The reason text of a real Allow Once (`AccessRequestsModel.answer`).
        #expect(prompts.reasons.contains { $0.hasPrefix("allow one scoped use attempt by") && $0.contains("Codex") })
        let posts = await demo.demo.service.accessPosts()
        #expect(posts.map(\.choice) == [.allow_once])
        #expect(posts.first?.signature != nil)
        let settled = demo.questions.access.requests.first { $0.id == request.id }
        #expect(settled?.receipt?.outcome == "allowed_once")
        #expect(world.calls.isEmpty)
    }

    @Test func aCancelledFaceIDSendsNothing() async throws {
        let prompts = Prompts()
        prompts.set(allow: false)
        let demo = await session(prompts: prompts)
        await started(demo)
        let request = try #require(demo.questions.access.requests.first { $0.id == DemoVault.accessRequestID })
        await demo.questions.access.answer(request, choice: .allow_once)
        #expect(await demo.demo.service.accessPosts().isEmpty)
        #expect(demo.questions.access.actionable(request))
    }

    @Test func denyNeedsNoFaceID() async throws {
        let prompts = Prompts()
        let demo = await session(prompts: prompts)
        await started(demo)
        let request = try #require(demo.questions.access.requests.first { $0.id == DemoVault.accessRequestID })
        await demo.questions.access.answer(request, choice: .deny)
        #expect(prompts.reasons.isEmpty)
        let settled = demo.questions.access.requests.first { $0.id == request.id }
        #expect(settled?.receipt?.outcome == "denied")
    }

    @Test func aLockedDemoOpensWithFaceIDAndTheStoredPassphrase() async throws {
        let prompts = Prompts()
        let world = FailingWorld()
        let demo = await session(world: world, prompts: prompts)
        await started(demo)
        await demo.vault.lock()
        #expect(!demo.vault.isUnlocked)
        #expect(demo.vault.faceIDUnlockOn && demo.vault.hasStoredPassphrase)
        await demo.vault.unlockWithFaceID()
        #expect(demo.vault.isUnlocked)
        #expect(!prompts.reasons.isEmpty)
        #expect(world.calls.isEmpty)
        #expect(demo.vault.gate.passphraseHint?.contains(DemoVault.passphrase) == true)
    }

    // MARK: - Memory only

    @Test func theDemoWritesNoDefaultsOfTheApp() async throws {
        let keys = [
            "lockAfter", "clearCopiedAfter", "deviceName", "faceIDUnlock.\(DemoVault.vaultID)",
            QuestionsModel.questionVaultsKey, QuestionsModel.notificationsKey,
        ]
        let group = UserDefaults(suiteName: SharedContainer.appGroup)
        let before = keys.map { (UserDefaults.standard.object(forKey: $0) as? NSObject, group?.object(forKey: $0) as? NSObject) }
        let demo = await session()
        await started(demo)
        demo.settings.lockAfter = .oneHour
        demo.settings.clearAfter = .twoMinutes
        demo.settings.toggleFavorite(100, vaultID: DemoVault.vaultID)
        let after = keys.map { (UserDefaults.standard.object(forKey: $0) as? NSObject, group?.object(forKey: $0) as? NSObject) }
        #expect(before.map(\.0) == after.map(\.0))
        #expect(before.map(\.1) == after.map(\.1))
        #expect(demo.demo.settings.keys.contains("lockAfter"))
    }

    @Test func notificationsInTheDemoAskIOSForNothing() async {
        let shown = Counter()
        let demo = await session(notAvailable: { shown.value += 1 })
        await started(demo)
        await demo.questions.setNotifications(true)
        #expect(shown.value == 1)
        #expect(demo.answerSigners.faceIDWindow == nil)
    }

    @Test func theDemoMakesNoNetworkRequest() async throws {
        DemoFailingURLProtocol.reset()
        URLProtocol.registerClass(DemoFailingURLProtocol.self)
        defer { URLProtocol.unregisterClass(DemoFailingURLProtocol.self) }
        let demo = await session()
        await started(demo)
        await demo.agents.refresh()
        await demo.vault.syncNow()
        #expect(DemoFailingURLProtocol.requests == 0)
    }

    // MARK: - Leaving, and the real vault

    @Test func leavingTheDemoDropsItsState() async {
        weak var weakSession: DemoAppSession?
        weak var weakVault: VaultModel?
        weak var weakQuestions: QuestionsModel?
        weak var weakService: PreviewVaultService?
        do {
            let demo = await session()
            await started(demo)
            weakSession = demo
            weakVault = demo.vault
            weakQuestions = demo.questions
            weakService = demo.demo.service
        }
        // Tasks of the models may hold them for a moment after the last reference goes.
        for _ in 0..<200 where weakService != nil || weakVault != nil {
            try? await Task.sleep(for: .milliseconds(10))
        }
        #expect(weakSession == nil)
        #expect(weakVault == nil)
        #expect(weakQuestions == nil)
        #expect(weakService == nil)
    }

    @Test func aRealVaultIsUnaffected() async throws {
        // The vault of the owner: its own service, hooks, and settings.
        let realService = PreviewVaultService()
        let realSettings = VaultSettings(defaults: MemorySettingsStore())
        let realHookCalls = Counter()
        var hooks = VaultModel.Hooks()
        hooks.replaceIdentities = { _, _ in realHookCalls.value += 1 }
        hooks.removeAllIdentities = { realHookCalls.value += 1 }
        hooks.copy = { _, _ in realHookCalls.value += 1 }
        let real = VaultModel(
            service: realService, settings: realSettings, gate: OwnerGate(check: ScriptedOwnerCheck(), service: realService),
            passphraseStore: MemoryPassphraseStore(), hooks: hooks)
        await real.start()
        let rows = real.items
        let stored = try await realService.items(archived: .all)
        let calls = realHookCalls.value

        let demo = await session()
        await started(demo)
        let first = try #require(demo.vault.activeItems.first)
        await demo.vault.setArchived(first, true)
        let request = try #require(demo.questions.access.requests.first { $0.id == DemoVault.accessRequestID })
        await demo.questions.access.answer(request, choice: .deny)
        await demo.vault.lock()

        #expect(real.isUnlocked)
        #expect(real.items == rows)
        #expect(try await realService.items(archived: .all) == stored)
        #expect(realHookCalls.value == calls)
        #expect(real.vault?.name == "Personal")
    }
}

/// Fails any request of the URL loading system, and counts it.
final class DemoFailingURLProtocol: URLProtocol, @unchecked Sendable {
    private static let count = Mutex(0)
    static var requests: Int { count.withLock { $0 } }
    static func reset() { count.withLock { $0 = 0 } }

    override class func canInit(with request: URLRequest) -> Bool {
        count.withLock { $0 += 1 }
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet))
    }

    override func stopLoading() {}
}
