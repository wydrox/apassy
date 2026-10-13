import ApassyCompanionKit
import ApassyVaultKit
import Foundation
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

    // MARK: The vaults and the questions

    func select(vaultID: String) async throws { selected = vaultID }

    private var current: Vault { vaults[selected]! }

    func questionsList() async throws -> QuestionsList {
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

    func pushTokenClear() async throws {
        pushTokens[current.team] = nil
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

/// An iPhone that holds two vaults, each with its own questions team (plan A2). The tests are
/// disabled until the fix lands: today each one fails when enabled.
@MainActor
@Suite("QuestionsModel with two vaults")
struct MultiVaultQuestionsTests {
    @MainActor
    fileprivate final class Fixture {
        let service = TwoVaultQuestionsService()
        let signer = ScriptedSigner()
        let push = ScriptedPush(allows: true)
        let defaults: UserDefaults
        let model: QuestionsModel

        init(notifications: Bool = false) {
            let suite = "questions-two-vaults-\(UUID().uuidString)"
            defaults = UserDefaults(suiteName: suite)!
            defaults.removePersistentDomain(forName: suite)
            if notifications { defaults.set(true, forKey: QuestionsModel.notificationsKey) }
            model = QuestionsModel(
                service: service, signer: signer, push: push, deviceName: "Test iPhone", defaults: defaults,
                retryInterval: .milliseconds(10))
        }
    }

    @Test(
        "the push token reaches the team of each vault that opens in this launch",
        .disabled(
            "A2 gap: the token goes only to the team of the vault selected when it arrives, once per launch (QuestionsModel.askedForToken, receivePushToken)"
        ))
    func tokenReachesEachVault() async throws {
        let fixture = Fixture(notifications: true)
        let (service, model) = (fixture.service, fixture.model)
        await service.setVault("vault-a", rowKey: fixture.signer.key, removed: false)
        await service.setVault("vault-b", rowKey: fixture.signer.key, removed: false)

        await model.refresh()
        await model.receivePushToken(Data([7, 7, 7]))
        #expect(await service.token(team: "t_aaaaaaaaaa") == Data([7, 7, 7]))

        try await service.select(vaultID: "vault-b")
        await model.refresh()
        #expect(await service.token(team: "t_bbbbbbbbbb") == Data([7, 7, 7]))
    }

    @Test(
        "turning notifications off clears the token in every team that has it",
        .disabled("A2 gap: push_token_clear reaches only the team of the selected vault"))
    func notificationsOffClearsEveryTeam() async throws {
        let fixture = Fixture(notifications: true)
        let (service, model) = (fixture.service, fixture.model)
        await service.setVault("vault-a", rowKey: fixture.signer.key, removed: false)
        await service.setVault("vault-b", rowKey: fixture.signer.key, removed: false)
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

    @Test(
        "reconnecting a removed vault keeps the answer key of the other vault",
        .disabled(
            "A2 gap: one answer key for every vault (EnclaveAnswerSigner.service); renewing it for one vault breaks the others. The fix gives each questions team its own key; adapt ScriptedSigner with it"
        ))
    func reconnectKeepsOtherVaultKey() async throws {
        let fixture = Fixture()
        let (service, model) = (fixture.service, fixture.model)
        let original = fixture.signer.key
        await service.setVault("vault-a", rowKey: original, removed: true)
        await service.setVault("vault-b", rowKey: original, removed: false)

        await model.refresh()
        #expect(model.status.removed)
        await model.startAttach(
            link: "https://apassy-relay.example/link#apassy_lnk_t_aaaaaaaaaa_00", pollInterval: .milliseconds(10))
        await model.attachFinished()
        #expect(model.attach == .attached)

        try await service.select(vaultID: "vault-b")
        await model.refresh()
        #expect(model.notice == nil)
        #expect(await service.rowKey(of: "vault-b") == original)
        #expect(model.status.registered)
    }
}
