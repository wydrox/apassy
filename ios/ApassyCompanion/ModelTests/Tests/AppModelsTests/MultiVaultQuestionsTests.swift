import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Synchronization
import Testing

@testable import AppModels

/// A service with two vaults, each with its own questions team, as an iPhone that holds two vaults.
/// `select` switches the vault; the question calls answer for the selected one. Unrelated vault
/// operations forward to the in-memory test service.
private actor TwoVaultQuestionsService: VaultService {
    struct Vault {
        let team: String
        /// The answer key in this iPhone's row of the vault.
        var rowKey: Data?
        var removed = false
        var attachKey: Data?
    }

    static let teamA = "t_aaaaaaaaaa"
    static let teamB = "t_bbbbbbbbbb"

    private let inner = SpyVaultService()
    private var vaults: [String: Vault] = [
        "vault-a": Vault(team: TwoVaultQuestionsService.teamA),
        "vault-b": Vault(team: TwoVaultQuestionsService.teamB),
    ]
    private var selected = "vault-a"
    private var pushTokens: [String: Data] = [:]

    // MARK: Test hooks

    func setVault(_ id: String, rowKey: Data?, removed: Bool) {
        vaults[id]?.rowKey = rowKey
        vaults[id]?.removed = removed
    }

    func setToken(_ token: Data?, team: String) { pushTokens[team] = token }

    func token(team: String) -> Data? { pushTokens[team] }

    func rowKey(of id: String) -> Data? { vaults[id]?.rowKey }

    /// The selected vault locks: its list fails as the core's does.
    func setLocked(_ locked: Bool) { self.locked = locked }

    private var locked = false

    // MARK: The vaults and the questions

    func select(vaultID: String) async throws { selected = vaultID }

    private var current: Vault { vaults[selected]! }

    func questionsList() async throws -> QuestionsList {
        if locked { throw VaultError(.locked, "The vault is locked.") }
        let vault = current
        return QuestionsList(
            status: QuestionsStatus(
                enabled: true, teamID: vault.team, relayDeviceID: 3,
                deviceUUID: vault.rowKey != nil ? "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b" : nil,
                answerKey: vault.removed ? nil : vault.rowKey, hasKey: true,
                registered: vault.rowKey != nil && !vault.removed, removed: vault.removed),
            questions: [])
    }

    func questionsWait(timeout: Int) async throws -> Bool {
        try? await Task.sleep(for: .milliseconds(10))
        return false
    }

    func answerKeyRegister(publicKey: Data) async throws -> AnswerKeyRegistration {
        let vault = current
        if vault.removed { throw VaultError(.removed, "This device was removed from questions.") }
        if let rowKey = vault.rowKey, rowKey != publicKey {
            throw VaultError(.answerKeyChanged, "The answer key of this iPhone changed.")
        }
        vaults[selected]?.rowKey = publicKey
        return AnswerKeyRegistration(
            deviceUUID: "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b", teamID: vault.team, relayDeviceID: 3)
    }

    func pushTokenSet(token: Data, environment: PushEnvironment) async throws {
        pushTokens[current.team] = token
    }

    func pushTokenClear() async throws -> PushCleared {
        pushTokens[current.team] = nil
        return PushCleared(cleared: [selected])
    }

    func joinAttach(link: String, deviceName: String, answerKey: Data) async throws -> AttachInfo {
        vaults[selected]?.attachKey = answerKey
        return AttachInfo(
            state: .waiting, team: "Notifications", words: ["amber", "marble"],
            expiresAt: Int64(Date().timeIntervalSince1970) + 600)
    }

    func joinAttachPoll() async throws -> AttachInfo {
        let attachKey = vaults[selected]?.attachKey
        vaults[selected]?.rowKey = attachKey
        vaults[selected]?.removed = false
        return AttachInfo(
            state: .attached, team: "Notifications", words: ["amber", "marble"],
            expiresAt: Int64(Date().timeIntervalSince1970) + 600)
    }

    func joinAttachCancel() async throws {}

    // MARK: Everything else forwards

    func info() async throws -> CoreInfo { try await inner.info() }
    func unlock(passphrase: String, keep: Bool) async throws { try await inner.unlock(passphrase: passphrase, keep: keep) }
    func lock() async throws { try await inner.lock() }
    func suspend() async throws { try await inner.suspend() }
    func resume() async throws -> Bool { try await inner.resume() }
    func checkPassphrase(_ passphrase: String) async throws -> Bool { try await inner.checkPassphrase(passphrase) }
    func createLocalVault(name: String, passphrase: String) async throws -> VaultEntry {
        try await inner.createLocalVault(name: name, passphrase: passphrase)
    }
    func removeVault(id: String, force: Bool) async throws -> Bool { try await inner.removeVault(id: id, force: force) }
    func joinStart(link: String, deviceName: String, answerKey: Data?) async throws -> JoinInfo {
        try await inner.joinStart(link: link, deviceName: deviceName, answerKey: answerKey)
    }
    func joinPoll() async throws -> JoinInfo { try await inner.joinPoll() }
    func joinCancel() async throws { try await inner.joinCancel() }
    func joinFinish(passphrase: String) async throws -> VaultEntry { try await inner.joinFinish(passphrase: passphrase) }
    func items(archived: ArchiveFilter) async throws -> [ItemRow] { try await inner.items(archived: archived) }
    func item(id: UInt64) async throws -> ItemDetail { try await inner.item(id: id) }
    func reveal(id: UInt64, field: String) async throws -> String { try await inner.reveal(id: id, field: field) }
    func totp(id: UInt64, field: String) async throws -> TotpCode { try await inner.totp(id: id, field: field) }
    func history(id: UInt64) async throws -> [ItemEvent] { try await inner.history(id: id) }
    func save(id: UInt64?, revision: UInt64?, draft: ItemDraft) async throws -> SavedItem {
        try await inner.save(id: id, revision: revision, draft: draft)
    }
    func archive(id: UInt64, archived: Bool) async throws { try await inner.archive(id: id, archived: archived) }
    func delete(id: UInt64, revision: UInt64) async throws { try await inner.delete(id: id, revision: revision) }
    func generate(_ options: GeneratorOptions) async throws -> GeneratedPassword { try await inner.generate(options) }
    func strength(_ value: String) async throws -> Strength { try await inner.strength(value) }
    func watchtower() async throws -> WatchtowerReport { try await inner.watchtower() }
    func sync() async throws -> SyncStatus { try await inner.sync() }
    func syncStatus() async throws -> SyncStatus { try await inner.syncStatus() }
    func syncWait(timeout: Int) async throws -> Bool { try await inner.syncWait(timeout: timeout) }
    func takeNewPassphrase(_ passphrase: String) async throws -> PassphraseChange {
        try await inner.takeNewPassphrase(passphrase)
    }
    func useRelayCopy() async throws -> SyncStatus { try await inner.useRelayCopy() }
    func devices() async throws -> [RelayDevice] { try await inner.devices() }
    func autofillList(domains: [String]) async throws -> AutofillList { try await inner.autofillList(domains: domains) }
    func autofillCredential(id: UInt64) async throws -> FillCredential { try await inner.autofillCredential(id: id) }
    func credentialIdentities() async throws -> [CredentialIdentity] { try await inner.credentialIdentities() }
}

/// Answer keys in memory by keychain service, as `KeychainAnswerKeyStore` keeps them. Each new key
/// is new bytes; a signature says which service signed it.
final class ScriptedKeyStore: AnswerKeyStore {
    private struct Keys: CompanionKeys {
        let service: String
        let approvalPublicKey: Data
        var requestPublicKey: Data { approvalPublicKey }
        var isSecureEnclave: Bool { false }
        func signRequest(_ message: Data) throws -> Data { Data() }
        func signApproval(_ message: Data, reason: String) async throws -> Data { Data("signed by \(service)".utf8) }
    }

    private let state = Mutex((keys: [String: Data](), made: UInt8(0), creates: [String]()))

    /// Add a key under `service` (an earlier version made it), and return its public key.
    @discardableResult
    func add(service: String) -> Data {
        state.withLock { state in
            state.made += 1
            let key = Data([4] + [UInt8](repeating: state.made, count: 64))
            state.keys[service] = key
            return key
        }
    }

    func key(service: String) -> Data? { state.withLock { $0.keys[service] } }

    /// The services that got a new key, in order.
    var creates: [String] { state.withLock { $0.creates } }

    func load(service: String) throws -> (any CompanionKeys)? {
        key(service: service).map { Keys(service: service, approvalPublicKey: $0) }
    }

    func create(service: String) throws -> any CompanionKeys {
        state.withLock { $0.creates.append(service) }
        return Keys(service: service, approvalPublicKey: add(service: service))
    }
}

/// An iPhone that holds two vaults, each with its own questions team (plan A2). With the selected
/// vault only in the list (an older core), the push token and its removal reach each team when its
/// vault is selected; each team has its own answer key.
@MainActor
@Suite("QuestionsModel with two vaults")
struct MultiVaultQuestionsTests {
    @MainActor
    fileprivate final class Fixture {
        let service = TwoVaultQuestionsService()
        let keys = ScriptedKeyStore()
        /// The one answer key of an earlier version, which both rows hold.
        let shared: Data
        let push = ScriptedPush(allows: true)
        let defaults: UserDefaults
        let model: QuestionsModel

        init(notifications: Bool = false) {
            let suite = "questions-two-vaults-\(UUID().uuidString)"
            defaults = UserDefaults(suiteName: suite)!
            defaults.removePersistentDomain(forName: suite)
            if notifications { defaults.set(true, forKey: QuestionsModel.notificationsKey) }
            shared = keys.add(service: TeamAnswerSigners.sharedService)
            model = QuestionsModel(
                service: service, signers: TeamAnswerSigners(store: keys), push: push, deviceName: "Test iPhone",
                defaults: defaults, retryInterval: .milliseconds(10))
        }
    }

    @Test("the push token reaches the team of each vault that opens in this launch")
    func tokenReachesEachVault() async throws {
        let fixture = Fixture(notifications: true)
        let (service, model) = (fixture.service, fixture.model)
        await service.setVault("vault-a", rowKey: fixture.shared, removed: false)
        await service.setVault("vault-b", rowKey: fixture.shared, removed: false)

        await model.refresh()
        await model.receivePushToken(Data([7, 7, 7]))
        #expect(await service.token(team: "t_aaaaaaaaaa") == Data([7, 7, 7]))

        try await service.select(vaultID: "vault-b")
        await model.refresh()
        #expect(await service.token(team: "t_bbbbbbbbbb") == Data([7, 7, 7]))
    }

    @Test("turning notifications off clears the token in every team that has it")
    func notificationsOffClearsEveryTeam() async throws {
        let fixture = Fixture(notifications: true)
        let (service, model) = (fixture.service, fixture.model)
        await service.setVault("vault-a", rowKey: fixture.shared, removed: false)
        await service.setVault("vault-b", rowKey: fixture.shared, removed: false)
        await service.setToken(Data([7, 7, 7]), team: "t_aaaaaaaaaa")
        await service.setToken(Data([7, 7, 7]), team: "t_bbbbbbbbbb")

        try await service.select(vaultID: "vault-b")
        await model.refresh()
        await model.setNotifications(false)
        try await service.select(vaultID: "vault-a")
        await model.refresh()

        #expect(await service.token(team: "t_aaaaaaaaaa") == nil)
        #expect(await service.token(team: "t_bbbbbbbbbb") == nil)
    }

    @Test("a team that is not open now is cleared when its vault opens, also after a new launch")
    func clearWaitsForTheVault() async throws {
        let fixture = Fixture(notifications: true)
        let service = fixture.service
        await service.setVault("vault-a", rowKey: fixture.shared, removed: false)
        await service.setVault("vault-b", rowKey: fixture.shared, removed: false)
        await service.setToken(Data([7]), team: "t_aaaaaaaaaa")
        await service.setToken(Data([7]), team: "t_bbbbbbbbbb")
        await fixture.model.refresh()
        await fixture.model.setNotifications(false)
        #expect(await service.token(team: "t_aaaaaaaaaa") == nil)

        // The next launch remembers the team that still has the token.
        let later = QuestionsModel(
            service: service, signers: TeamAnswerSigners(store: fixture.keys), push: fixture.push,
            deviceName: "Test iPhone", defaults: fixture.defaults, retryInterval: .milliseconds(10))
        try await service.select(vaultID: "vault-b")
        await later.refresh()
        #expect(await service.token(team: "t_bbbbbbbbbb") == nil)

        // Turned on again: nothing more is cleared, and the token goes again.
        await later.setNotifications(true)
        await later.receivePushToken(Data([8]))
        #expect(await service.token(team: "t_bbbbbbbbbb") == Data([8]))
        try await service.select(vaultID: "vault-a")
        await later.refresh()
        #expect(await service.token(team: "t_aaaaaaaaaa") == Data([8]))
    }

    @Test("reconnecting a removed vault keeps the answer key of the other vault")
    func reconnectKeepsOtherVaultKey() async throws {
        let fixture = Fixture()
        let (service, model) = (fixture.service, fixture.model)
        let original = fixture.shared
        await service.setVault("vault-a", rowKey: original, removed: true)
        await service.setVault("vault-b", rowKey: original, removed: false)

        await model.refresh()
        #expect(model.status.removed)
        await model.startAttach(
            link: "https://apassy-relay.example/link#apassy_lnk_t_aaaaaaaaaa_00", pollInterval: .milliseconds(10))
        await model.attachFinished()
        #expect(model.attach == .attached)
        // Vault A got a key of its own team; the shared key stays as it was.
        let own = fixture.keys.key(service: "com.wydrox.apassy.questions.t_aaaaaaaaaa")
        #expect(own != nil && own != original)
        #expect(await service.rowKey(of: "vault-a") == own)
        #expect(fixture.keys.key(service: TeamAnswerSigners.sharedService) == original)
        #expect(fixture.keys.creates == ["com.wydrox.apassy.questions.t_aaaaaaaaaa"])

        try await service.select(vaultID: "vault-b")
        await model.refresh()
        #expect(model.notice == nil)
        #expect(await service.rowKey(of: "vault-b") == original)
        #expect(model.status.registered)
    }

    @Test("a locked vault says so instead of an empty list")
    func lockedVaultIsShown() async {
        let fixture = Fixture()
        await fixture.service.setVault("vault-a", rowKey: fixture.shared, removed: false)
        await fixture.model.refresh()
        #expect(fixture.model.phase == .ready)
        await fixture.service.setLocked(true)
        await fixture.model.refresh()
        #expect(fixture.model.phase == .locked)
        #expect(fixture.model.questions.isEmpty)
        await fixture.service.setLocked(false)
        await fixture.model.refresh()
        #expect(fixture.model.phase == .ready)
    }
}

/// The answer keys of this iPhone, one per questions team (`TeamAnswerSigners`).
@Suite("Answer keys per team")
struct AnswerSignersTests {
    let teamA = "t_aaaaaaaaaa"
    let teamB = "t_bbbbbbbbbb"

    @Test("a new team gets its own key; a team whose row holds the shared key keeps it")
    func ownKeyAndSharedKey() throws {
        let keys = ScriptedKeyStore()
        let shared = keys.add(service: TeamAnswerSigners.sharedService)
        let signers = TeamAnswerSigners(store: keys)

        // A row of an earlier version: the shared key answers for it, and nothing is made.
        #expect(signers.resolvedService(team: teamA, registered: shared) == TeamAnswerSigners.sharedService)
        #expect(try signers.signer(team: teamA, registered: shared)?.publicKey() == shared)
        #expect(keys.creates.isEmpty)

        // A new connection to team B makes the key of team B, once.
        let ownB = try signers.joinKey(team: teamB)
        #expect(ownB != shared)
        #expect(try signers.joinKey(team: teamB) == ownB)
        #expect(keys.creates == ["com.wydrox.apassy.questions.t_bbbbbbbbbb"])
        #expect(try signers.signer(team: teamB, registered: ownB)?.publicKey() == ownB)
        // Team A still answers with the shared key.
        #expect(try signers.signer(team: teamA, registered: shared)?.publicKey() == shared)
    }

    @Test("the key whose public key the row holds signs")
    func theRowKeySigns() async throws {
        let keys = ScriptedKeyStore()
        let shared = keys.add(service: TeamAnswerSigners.sharedService)
        let signers = TeamAnswerSigners(store: keys)
        let ownA = try signers.joinKey(team: teamA)

        let byShared = try await signers.signer(team: teamA, registered: shared)?.sign(Data(), reason: "r")
        #expect(byShared == Data("signed by com.wydrox.apassy.questions".utf8))
        let byOwn = try await signers.signer(team: teamA, registered: ownA)?.sign(Data(), reason: "r")
        #expect(byOwn == Data("signed by com.wydrox.apassy.questions.t_aaaaaaaaaa".utf8))
    }

    @Test("renew replaces the key of one team only, never the shared key")
    func renewOneTeam() throws {
        let keys = ScriptedKeyStore()
        let shared = keys.add(service: TeamAnswerSigners.sharedService)
        let signers = TeamAnswerSigners(store: keys)
        let ownB = try signers.joinKey(team: teamB)

        let renewedA = try signers.renew(team: teamA)
        #expect(keys.key(service: TeamAnswerSigners.service(team: teamA)) == renewedA)
        #expect(keys.key(service: TeamAnswerSigners.service(team: teamB)) == ownB)
        #expect(keys.key(service: TeamAnswerSigners.sharedService) == shared)

        // The renew of a signer that answers with the shared key makes the key of its team.
        let renewedB = try signers.signer(team: teamB, registered: ownB)!.renew()
        #expect(keys.key(service: TeamAnswerSigners.service(team: teamB)) == renewedB)
        _ = try signers.signer(team: "t_cccccccccc", registered: shared)!.renew()
        #expect(keys.key(service: TeamAnswerSigners.sharedService) == shared)
    }

    @Test("no key for a team: no signer, and none is made")
    func noKey() {
        let keys = ScriptedKeyStore()
        let signers = TeamAnswerSigners(store: keys)
        #expect(signers.signer(team: teamA, registered: Data([4])) == nil)
        #expect(keys.creates.isEmpty)
    }
}

/// A core that keeps the questions of every unlocked vault (`PreviewVaultService` with a second
/// vault): the list names the vault of each question, and the answers and the push token follow.
@MainActor
@Suite("QuestionsModel with a core that lists every vault")
struct EveryVaultQuestionsTests {
    static let work = (id: "8e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b", name: "Work", team: "t_wq3k7m2p5x")
    static let personalID = "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c"

    @MainActor
    final class Fixture {
        let service = PreviewVaultService()
        let keys = ScriptedKeyStore()
        let push = ScriptedPush(allows: true)
        let defaults: UserDefaults
        let model: QuestionsModel
        let personal: RemoteQuestion
        let work: RemoteQuestion

        init(now: Date = Date()) async throws {
            let suite = "questions-every-vault-\(UUID().uuidString)"
            defaults = UserDefaults(suiteName: suite)!
            defaults.removePersistentDomain(forName: suite)
            let signers = TeamAnswerSigners(store: keys)
            model = QuestionsModel(
                service: service, signers: signers, push: push, deviceName: "Test iPhone", defaults: defaults,
                retryInterval: .milliseconds(10))
            var personal = PreviewVaultService.sampleQuestion(qid: "cGVyc29uYWwtcXVlc3Rpb24tMQ", now: now.addingTimeInterval(-60))
            personal.askerName = "Mac mini"
            self.personal = personal
            var work = PreviewVaultService.sampleQuestion(qid: "d29yay1xdWVzdGlvbi0wMDAwMQ", now: now)
            work.askerName = "MacBook Pro"
            self.work = work
            await service.setQuestions(
                enabled: true, questions: [personal], answerKey: try signers.joinKey(team: "t_7k2m5q4x3c"))
            await service.addQuestionsVault(
                id: EveryVaultQuestionsTests.work.id, name: EveryVaultQuestionsTests.work.name,
                team: EveryVaultQuestionsTests.work.team, questions: [work],
                answerKey: try signers.joinKey(team: EveryVaultQuestionsTests.work.team))
            await model.refresh()
        }
    }

    @Test("the questions of two vaults show, each row with its vault and Mac")
    func twoVaultsWithNames() async throws {
        let fixture = try await Fixture()
        let model = fixture.model
        #expect(model.phase == .ready)
        #expect(model.vaults.map(\.vaultName) == ["Personal", "Work"])
        #expect(model.namesVaults)
        #expect(model.notice == nil)
        #expect(Set(model.questions.map(\.qid)) == [fixture.personal.qid, fixture.work.qid])

        let rows = Decisions.waiting(
            questions: model.questions, session: nil, namesVaults: model.namesVaults, now: Date())
        #expect(rows.map(\.vault) == ["Work · MacBook Pro", "Personal · Mac mini"])
        // One vault: no vault line.
        let single = Decisions.waiting(questions: model.questions, session: nil, now: Date())
        #expect(single.allSatisfy { $0.vault == nil })
    }

    @Test("an answer names the vault of its question, and the key of that vault's team signs")
    func answerCarriesVaultID() async throws {
        let fixture = try await Fixture()
        let model = fixture.model
        let work = try #require(model.questions.first { $0.qid == fixture.work.qid })
        let bar = AnswerBar.make(for: work.card!)
        await model.send(bar.primary!, for: work)
        await model.send(bar.deny, for: try #require(model.questions.first { $0.qid == fixture.personal.qid }))

        let sent = await fixture.service.sentAnswers()
        #expect(sent.map(\.qid) == [fixture.work.qid, fixture.personal.qid])
        #expect(sent.map(\.vaultID) == [Self.work.id, Self.personalID])
        #expect(sent[0].signature == Data("signed by com.wydrox.apassy.questions.\(Self.work.team)".utf8))
        #expect(sent[1].signature == nil)
        #expect(model.deliveries[fixture.work.qid] == .sent(.allowProduction))
    }

    @Test("a generic notification refreshes all open vaults without selecting a question")
    func notificationOpensOtherVault() async throws {
        let fixture = try await Fixture()
        fixture.push.open()
        let qid = await fixture.model.takeFocus(stillFree: { true })
        #expect(qid == nil)
        #expect(fixture.model.questions.contains { $0.qid == fixture.work.qid && $0.vaultID == Self.work.id })
    }

    @Test("the push token reaches every team at once, and turning notifications off clears every team")
    func pushReachesEveryTeam() async throws {
        let fixture = try await Fixture()
        let (service, model) = (fixture.service, fixture.model)
        await model.setNotifications(true)
        await model.receivePushToken(Data([9, 9]))
        #expect(await service.currentPushToken() == Data([9, 9]))
        #expect(await service.pushToken(vaultID: Self.work.id) == Data([9, 9]))

        await model.setNotifications(false)
        #expect(await service.currentPushToken() == nil)
        #expect(await service.pushToken(vaultID: Self.work.id) == nil)
        #expect(
            Set(fixture.defaults.stringArray(forKey: QuestionsModel.pushClearedKey) ?? [])
                == ["t_7k2m5q4x3c", Self.work.team])
    }

    @Test("the token is sent again when another vault joins the list")
    func tokenFollowsANewVault() async throws {
        let fixture = try await Fixture()
        let (service, model) = (fixture.service, fixture.model)
        await model.setNotifications(true)
        await model.receivePushToken(Data([5]))
        await service.addQuestionsVault(
            id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9", name: "Family", team: "t_fffffffff2")
        await model.refresh()
        #expect(await service.pushToken(vaultID: "0a1b2c3d4e5f60718293a4b5c6d7e8f9") == Data([5]))
    }
}
