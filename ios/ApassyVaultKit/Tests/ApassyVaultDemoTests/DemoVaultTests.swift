import Foundation
import Testing

@testable import ApassyVaultDemo
@testable import ApassyVaultKit

/// The demo of the store build ("Try the Demo", `-ApassyDemo`): its content, that it stays in
/// memory, and that leaving it drops it. Synthetic data only.
@MainActor
@Suite(.serialized) struct DemoVaultTests {
    /// The owner check of the tests: confirms, and counts.
    final class Checks: @unchecked Sendable {
        private let lock = NSLock()
        private var reasons: [String] = []
        var allow = true
        var count: Int { lock.withLock { reasons.count } }
        func confirm(_ reason: String) -> Bool {
            lock.withLock { reasons.append(reason) }
            return allow
        }
    }

    private func session(_ checks: Checks = Checks()) async -> DemoSession {
        await DemoSession.open(confirm: { checks.confirm($0) })
    }

    // MARK: - Content

    @Test func theDemoVaultIsUnlockedAndOnlyOnThisIPhone() async throws {
        let demo = await session()
        let info = try await demo.service.info()
        #expect(info.unlocked)
        #expect(info.vaults.map(\.name) == [DemoVault.name])
        #expect(info.selectedVault?.syncs == false)
        #expect(try await demo.service.syncStatus().enabled == false)
    }

    @Test func theDemoHasEveryKindOfCredential() async throws {
        let demo = await session()
        let rows = try await demo.service.items(archived: .all)
        let active = rows.filter { !$0.archived }
        #expect(active.contains { $0.kind == .login && !$0.websites.isEmpty && $0.hasTotp })
        #expect(active.contains { $0.kind == .login && $0.hasPasskey })
        #expect(active.contains { $0.kind == .apiKey })
        #expect(active.contains { $0.kind == .sshKey })
        #expect(active.contains { $0.title == "Recovery notes" })
        let note = try #require(active.first { $0.title == "Recovery notes" })
        #expect(try await demo.service.item(id: note.id).notes.isEmpty == false)
        let folders = try await demo.service.folders()
        #expect(folders.count >= 2)
        #expect(active.contains { $0.folder == PreviewOrganize.FolderID.personal })
    }

    @Test func findDuplicatesFindsThePlantedDuplicate() async throws {
        let demo = await session()
        let groups = try await demo.service.duplicates()
        let titles = groups.map { Set($0.items.map(\.title)) }
        #expect(titles.contains { $0.isSuperset(of: ["Netflix", "Netflix (old)"]) })
    }

    @Test func revealAndCodesGiveSyntheticValues() async throws {
        let demo = await session()
        let rows = try await demo.service.items(archived: .no)
        let shop = try #require(rows.first { $0.title == "Example Shop" })
        let detail = try await demo.service.item(id: shop.id)
        let password = try #require(detail.fields.first { $0.role == .password })
        #expect(try await demo.service.reveal(id: shop.id, field: password.name).hasPrefix("synthetic-"))
        let code = try #require(detail.fields.first { $0.role == .totp })
        let totp = try await demo.service.totp(id: shop.id, field: code.name)
        #expect(totp.code.count == 6 && totp.period == 30)
    }

    @Test func oneRunQuestionAndOneAccessRequestWaitFromTheDemoMac() async throws {
        let demo = await session()
        let questions = try await demo.service.questionsList().questions
        #expect(questions.map(\.qid) == [DemoVault.runQuestionID])
        #expect(questions.first?.askerName == DemoVault.macName)
        #expect(questions.first?.state == .open)
        let open = try await demo.service.accessRequestsList().requests.filter { $0.state == "open" }
        #expect(open.map(\.id) == [DemoVault.accessRequestID])
        #expect(open.first?.card.asker.name == DemoVault.macName)
        // The row holds the demo answer key, so Allow once can sign.
        #expect(open.first?.answer_key == Base64URL.encode(demo.answerKey.publicKey))
    }

    @Test func historyAndAgentsHaveContent() async throws {
        let demo = await session()
        let history = try await demo.service.requestHistory()
        #expect(history.vaults.flatMap(\.entries).count >= 2)
        #expect(try await demo.service.accessRequestsHistory().requests.contains { $0.receipt != nil })
        let feed = try await demo.service.feedList()
        #expect(feed.vaults.count == 1)
        #expect(feed.vaults.first?.vaultName == DemoVault.name)
        #expect(feed.vaults.first?.macs.first?.name == DemoVault.macName)
        let agents = feed.vaults.flatMap(\.macs).flatMap(\.agents)
        #expect(agents.contains { $0.usesThisWeek > 0 && !$0.recent.isEmpty })
    }

    // MARK: - Simulated answers

    @Test func allowOnceAndDenyResolveInMemory() async throws {
        let demo = await session()
        let request = try #require(try await demo.service.accessRequestsList().requests.first { $0.state == "open" })
        let prepared = try await demo.service.accessRequestPrepare(request, choice: .allow_once)
        let signature = try demo.answerKey.sign(Data(prepared.bytes.utf8))
        let sent = try await demo.service.accessRequestAnswer(
            request, choice: .allow_once, prepared: prepared, signature: signature)
        #expect(sent.sent)
        let settled = try await demo.service.accessRequestsList().requests.first { $0.id == request.id }
        #expect(settled?.receipt?.outcome == "allowed_once")
    }

    @Test func theStoredPassphraseAsksTheOwnerEachTime() async throws {
        let checks = Checks()
        let demo = await session(checks)
        #expect(demo.passphraseStore.hasPassphrase(vaultID: DemoVault.vaultID))
        #expect(try await demo.passphraseStore.read(vaultID: DemoVault.vaultID, reason: "Unlock") == DemoVault.passphrase)
        #expect(checks.count == 1)
        checks.allow = false
        await #expect(throws: VaultError.self) {
            _ = try await demo.passphraseStore.read(vaultID: DemoVault.vaultID, reason: "Unlock")
        }
        #expect(checks.count == 2)
        #expect(try await demo.service.checkPassphrase(DemoVault.passphrase))
    }

    // MARK: - Memory only

    @Test func settingsStayInMemory() async {
        let demo = await session()
        let key = "demo.test.\(UUID().uuidString)"
        demo.settings.set(true, forKey: key)
        demo.settings.set(["a"], forKey: "\(key).list")
        #expect(demo.settings.bool(forKey: key))
        #expect(demo.settings.stringArray(forKey: "\(key).list") == ["a"])
        #expect(UserDefaults.standard.object(forKey: key) == nil)
        #expect(UserDefaults(suiteName: SharedContainer.appGroup)?.object(forKey: key) == nil)
        #expect(demo.settings.integerLike("lockAfter") == 300)
        #expect(demo.settings.bool(forKey: "faceIDUnlock.\(DemoVault.vaultID)"))
    }

    @Test func theDemoMakesNoNetworkRequest() async throws {
        FailingURLProtocol.reset()
        URLProtocol.registerClass(FailingURLProtocol.self)
        defer { URLProtocol.unregisterClass(FailingURLProtocol.self) }
        let demo = await session()
        let service = demo.service
        _ = try await service.sync()
        _ = try await service.devices()
        try await service.pushTokenSet(token: Data([1, 2, 3]), environment: .development)
        _ = try await service.questionsList()
        _ = try await service.feedList()
        _ = try await service.accessRequestsList()
        _ = try await service.identitySet()
        _ = try await service.credentialIdentities()
        _ = try await service.watchtower()
        _ = try await service.generate(GeneratorOptions())
        #expect(FailingURLProtocol.requests == 0)
    }

    @Test func leavingTheDemoDropsAllOfIt() async {
        weak var weakService: PreviewVaultService?
        weak var weakSettings: MemorySettingsStore?
        weak var weakStore: DemoPassphraseStore?
        do {
            let demo = await session()
            weakService = demo.service
            weakSettings = demo.settings
            weakStore = demo.passphraseStore
            #expect(weakService != nil)
        }
        #expect(weakService == nil)
        #expect(weakSettings == nil)
        #expect(weakStore == nil)
    }

    @Test func aRealVaultIsUnaffected() async throws {
        // A stand-in for the vault of the owner, with its own items.
        let real = PreviewVaultService()
        let before = try await real.items(archived: .all)
        let demo = await session()
        let rows = try await demo.service.items(archived: .no)
        let first = try #require(rows.first)
        try await demo.service.archive(id: first.id, archived: true)
        _ = try await demo.service.save(
            id: nil, revision: nil,
            draft: ItemDraft(title: "Made in the demo", kind: .custom, notes: "", tags: [], fields: []))
        #expect(try await real.items(archived: .all) == before)
        #expect(try await real.info().vaults.map(\.name) == ["Personal"])
    }

    // MARK: - The watch

    @Test func theWatchSampleResolvesLocally() async throws {
        let model = DemoWatch.model()
        await model.scenePhaseChanged(.active)
        #expect(model.screen == .requests)
        let id = try #require(model.requests.rows.first?.id)
        #expect(model.requests.rows.first?.card.asker.name == DemoVault.macName)
        #expect(model.requests.phase(for: id, at: .now) == .decide(allowOnce: true, notes: []))
        model.requests.answer(id, choice: .deny)
        await model.requests.answerFinished()
        guard case .result(let result) = model.requests.phase(for: id, at: .now) else {
            Issue.record("not a result")
            return
        }
        #expect(result.outcome == .denied)
    }

    @Test func theWatchSampleAllowsOnceInMemory() async throws {
        let model = DemoWatch.model()
        await model.scenePhaseChanged(.active)
        let id = try #require(model.requests.rows.first?.id)
        model.requests.answer(id, choice: .allow_once)
        await model.requests.answerFinished()
        #expect(model.requests.isConfirmedHere(id))
    }
}

extension MemorySettingsStore {
    fileprivate func integerLike(_ key: String) -> Int? { object(forKey: key) as? Int }
}

/// Fails any request of the URL loading system, and counts it.
final class FailingURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var count = 0
    static var requests: Int { lock.withLock { count } }
    static func reset() { lock.withLock { count = 0 } }

    override class func canInit(with request: URLRequest) -> Bool {
        lock.withLock { count += 1 }
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet))
    }

    override func stopLoading() {}
}
