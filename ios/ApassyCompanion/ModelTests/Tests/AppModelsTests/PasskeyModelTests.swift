import ApassyVaultKit
import AuthenticationServices
import CryptoKit
import Foundation
import Testing

@testable import AppModels

// Passkeys in the app: the item screen, the editor, the identities for iOS, and Apple's credential
// exchange. The preview vault does the passkey arithmetic; the values are synthetic.

private let hash = Data(repeating: 3, count: 32)

/// A passkey-only login in the preview vault.
private func addPasskey(_ service: PreviewVaultService, rpID: String = "example.com") async throws -> PasskeyCreated {
    try await service.passkeyRegister(
        PasskeyRegistration(
            rpID: rpID, userName: "ada", userDisplayName: "Ada", userHandle: Data([1, 2]), clientDataHash: hash,
            algorithms: [-7], excluded: [], attach: nil, title: "Example"))
}

@MainActor
@Suite("Passkeys in the app")
struct PasskeyModelTests {
    private func unlockedVault(check: ScriptedOwnerCheck = ScriptedOwnerCheck()) async -> (VaultModel, PreviewVaultService) {
        let service = PreviewVaultService(empty: false, unlocked: true)
        let (vault, _) = makeVault(service: service, check: check)
        await vault.start()
        vault.stopSync()
        return (vault, service)
    }

    @Test("the item screen shows the passkey and no field of its key")
    func detailShowsMetadata() async throws {
        let (vault, service) = await unlockedVault()
        let created = try await addPasskey(service)
        let detail = ItemDetailModel(id: created.id, vault: vault)
        await detail.load()
        #expect(detail.detail?.passkey?.rpID == "example.com")
        #expect(detail.isPasskeyOnly)
        #expect(detail.detail?.fields.allSatisfy { !$0.secret } == true)
    }

    @Test("removing a passkey asks the owner each time and keeps the login")
    func removeAsksTheOwner() async throws {
        let check = ScriptedOwnerCheck(answer: false)
        let (vault, service) = await unlockedVault(check: check)
        let created = try await addPasskey(service)
        // Give the login a password, so the passkey can go.
        var detail = try await service.item(id: created.id)
        let draft = ItemDraft(
            title: detail.row.title, kind: .login, notes: "", tags: [],
            fields: detail.fields.map { .named($0.name, $0.value, secret: false) } + [.named("password", "synthetic-pw", secret: true)])
        _ = try await service.save(id: created.id, revision: detail.row.revision, draft: draft)
        await vault.reload()

        let model = ItemDetailModel(id: created.id, vault: vault)
        await model.load()
        // The owner says no (and has no passphrase to type): nothing changes.
        let plan = try #require(model.passkeyRemovalPlan)
        #expect(plan.effect == .removesPasskey)
        let refused = Task { await model.removePasskey(plan) }
        #expect(await waitUntil { vault.gate.prompt != nil })
        vault.gate.cancel()
        #expect(await refused.value == false)
        #expect(try await service.item(id: created.id).passkey != nil)

        check.answer = true
        #expect(await model.removePasskey(plan))
        #expect(check.calls == 2)
        detail = try await service.item(id: created.id)
        #expect(detail.passkey == nil && !detail.row.hasPasskey)
        #expect(detail.row.title == "Example")
    }

    /// A login with a passkey, notes, a tag, and a one-time password; it has a password only when
    /// `password` is given.
    private func passkeyOnlyLogin(_ service: PreviewVaultService, password: String? = nil, notes: String = "recovery: see safe")
        async throws -> UInt64
    {
        let created = try await addPasskey(service)
        let detail = try await service.item(id: created.id)
        let draft = ItemDraft(
            title: "Example", kind: .login, notes: notes, tags: ["work"],
            fields: [
                .named("username", "ada", secret: false),
                .detail("One-time password", "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP", secret: true),
            ] + (password.map { [.named("password", $0, secret: true)] } ?? []))
        _ = try await service.save(id: created.id, revision: detail.row.revision, draft: draft)
        return created.id
    }

    @Test("a passkey-only login is deleted whole, and the owner check says so")
    func passkeyOnlyRemovalDeletesTheLogin() async throws {
        let check = ScriptedOwnerCheck()
        let (vault, service) = await unlockedVault(check: check)
        let id = try await passkeyOnlyLogin(service)
        await vault.reload()
        vault.toggleFavorite(id)
        let model = ItemDetailModel(id: id, vault: vault)
        await model.load()

        let plan = try #require(model.passkeyRemovalPlan)
        #expect(plan.deletesLogin && model.isPasskeyOnly)
        #expect(await model.removePasskey(plan))
        #expect(model.isGone)
        #expect(check.reasons == [plan.ownerReason])
        #expect(check.reasons.first?.contains("Delete the login") == true)
        await #expect(throws: VaultError.self) { _ = try await service.item(id: id) }
        #expect(!vault.isFavorite(id))
        #expect(vault.item(id) == nil)
    }

    @Test("a login with a password and a passkey keeps its notes and codes")
    func removalWithAPasswordKeepsTheLogin() async throws {
        let check = ScriptedOwnerCheck()
        let (vault, service) = await unlockedVault(check: check)
        let id = try await passkeyOnlyLogin(service, password: "synthetic-pw")
        await vault.reload()
        let model = ItemDetailModel(id: id, vault: vault)
        await model.load()

        let plan = try #require(model.passkeyRemovalPlan)
        #expect(!plan.deletesLogin && !model.isPasskeyOnly)
        #expect(await model.removePasskey(plan))
        #expect(!model.isGone && model.passkeyRemovalPlan == nil)
        #expect(check.reasons == [plan.ownerReason])
        let after = try await service.item(id: id)
        #expect(after.passkey == nil && after.notes == "recovery: see safe" && after.row.tags == ["work"])
        #expect(after.row.hasTotp)
    }

    @Test("a removal made for an older revision deletes nothing")
    func staleRemovalIsRefused() async throws {
        let (vault, service) = await unlockedVault()
        let id = try await passkeyOnlyLogin(service)
        await vault.reload()
        let model = ItemDetailModel(id: id, vault: vault)
        await model.load()
        let plan = try #require(model.passkeyRemovalPlan)
        // The login changes (a sync, or an edit) while the dialog is open.
        let detail = try await service.item(id: id)
        _ = try await service.save(
            id: id, revision: detail.row.revision,
            draft: ItemDraft(
                title: "Example", kind: .login, notes: "newer note", tags: [],
                fields: [.named("username", "ada", secret: false)]))
        #expect(await model.removePasskey(plan) == false)
        #expect(!model.isGone)
        #expect(try await service.item(id: id).notes == "newer note")
    }

    @Test("an edit of a passkey-only login needs no password and keeps the passkey")
    func editKeepsThePasskey() async throws {
        let (vault, service) = await unlockedVault()
        let created = try await addPasskey(service)
        let editor = ItemEditorModel(detail: try await service.item(id: created.id))
        #expect(editor.passkey?.rpID == "example.com")
        #expect(editor.specs.allSatisfy { !$0.required })
        editor.title = "Renamed"
        #expect(!editor.draft().fields.contains { $0.name == "password" })
        #expect(await editor.save(in: vault) != nil)
        let after = try await service.item(id: created.id)
        #expect(after.row.title == "Renamed" && after.passkey != nil)
    }

    @Test("the app gives iOS the passkeys and the one-time passwords with the logins")
    func identitiesHavePasskeys() async throws {
        let service = PreviewVaultService(empty: false, unlocked: true)
        let created = try await addPasskey(service)
        var published: [IdentitySet] = []
        var hooks = VaultModel.Hooks()
        hooks.replaceIdentities = { set, _ in published.append(set) }
        let model = VaultModel(
            service: service, settings: makeSettings(), gate: OwnerGate(check: ScriptedOwnerCheck(), service: service),
            passphraseStore: MemoryPassphraseStore(), hooks: hooks)
        await model.start()
        model.stopSync()
        let set = try #require(published.last)
        #expect(set.passkeys.map(\.credentialID) == [created.credentialID])
        #expect(set.codes.contains { $0.host == "github.com" })
    }
}

/// A system side of the credential exchange that records its calls.
@available(macOS 26.0, *)
@MainActor
private final class FakeExchange {
    var data: ASExportedCredentialData?
    var importError: (any Error)?
    var requestError: (any Error)?
    /// Runs while the sheet of the system is up (the app can leave the screen then).
    var duringRequest: (@MainActor () async -> Void)?
    var tokens: [UUID] = []
    var requests = 0
    var exported: [ASExportedCredentialData] = []

    var system: CredentialExchangeModel.System {
        CredentialExchangeModel.System(
            importCredentials: { [self] token in
                tokens.append(token)
                if let importError { throw importError }
                return data!
            },
            requestExport: { [self] in
                requests += 1
                await duringRequest?()
                if let requestError { throw requestError }
                return .v1
            },
            exportCredentials: { [self] data in exported.append(data) })
    }
}

/// Swift Testing takes no `@available` test, so each test checks the OS and runs a case here.
@MainActor
@Suite("Credential exchange")
struct CredentialExchangeModelTests {
    @Test("an import waits for the owner, and a refusal reads nothing")
    func importNeedsTheOwner() async throws {
        guard #available(macOS 26.0, *) else { return }
        try await CredentialExchangeCases().importNeedsTheOwner()
    }

    @Test("an import that the system cancels changes nothing")
    func importCancelled() async throws {
        guard #available(macOS 26.0, *) else { return }
        try await CredentialExchangeCases().importCancelled()
    }

    @Test("an export asks the owner, then the system, and hands over the passkeys")
    func exportHandsOver() async throws {
        guard #available(macOS 26.0, *) else { return }
        try await CredentialExchangeCases().exportHandsOver()
    }

    @Test("an export that the owner or the system cancels hands over nothing")
    func exportCancelled() async throws {
        guard #available(macOS 26.0, *) else { return }
        try await CredentialExchangeCases().exportCancelled()
    }

    @Test("an export never takes the data of another vault that the owner opened during the pick")
    func exportDoesNotFollowAnotherVaultOpenedDuringThePick() async throws {
        guard #available(macOS 26.0, *) else { return }
        try await CredentialExchangeCases().exportDoesNotFollowAnotherVaultOpenedDuringThePick()
    }

    @Test("an export that waits ignores another vault, and goes on only in its own vault after a new owner check")
    func exportWaitsForItsOwnVault() async throws {
        guard #available(macOS 26.0, *) else { return }
        try await CredentialExchangeCases().exportWaitsForItsOwnVault()
    }

    @Test("a canceled export that waited cannot be continued")
    func aCanceledPausedExportIsGone() async throws {
        guard #available(macOS 26.0, *) else { return }
        try await CredentialExchangeCases().aCanceledPausedExportIsGone()
    }

    @Test("an export whose vault locked during the pick waits, reads nothing, and goes on after the unlock")
    func exportSurvivesALockDuringThePick() async throws {
        guard #available(macOS 26.0, *) else { return }
        try await CredentialExchangeCases().exportSurvivesALockDuringThePick()
    }
}

@available(macOS 26.0, *)
@MainActor
private struct CredentialExchangeCases {
    private func setUp(check: ScriptedOwnerCheck = ScriptedOwnerCheck()) async -> (CredentialExchangeModel, VaultModel, PreviewVaultService, FakeExchange) {
        let service = PreviewVaultService(empty: false, unlocked: true)
        let (vault, _) = makeVault(service: service, check: check)
        await vault.start()
        vault.stopSync()
        let fake = FakeExchange()
        return (CredentialExchangeModel(vault: vault, system: fake.system), vault, service, fake)
    }

    private static func exported(key: Data) -> ASExportedCredentialData {
        let item = ASImportableItem(
            id: Data([1]), created: Date(), lastModified: Date(), title: "Example",
            credentials: [
                .basicAuthentication(.init(
                    userName: ASImportableEditableField(id: nil, fieldType: .string, value: "ada"),
                    password: ASImportableEditableField(id: nil, fieldType: .concealedString, value: "synthetic-pw"))),
                .passkey(.init(
                    credentialID: Data([7, 7]), relyingPartyIdentifier: "example.com", userName: "ada",
                    userDisplayName: "Ada", userHandle: Data([1]), key: key)),
            ])
        return ASExportedCredentialData(
            accounts: [ASImportableAccount(id: Data([1]), userName: "", email: "", collections: [], items: [item])],
            formatVersion: .v1, exporterRelyingPartyIdentifier: "exporter.example", exporterDisplayName: "Exporter",
            timestamp: Date())
    }

    func importNeedsTheOwner() async throws {
        let check = ScriptedOwnerCheck(answer: false)
        let (model, vault, service, fake) = await setUp(check: check)
        fake.data = Self.exported(key: P256.Signing.PrivateKey().derRepresentation)
        model.receive(token: UUID())
        #expect(model.state == .importWaiting)
        let refused = Task { await model.importNow() }
        #expect(await waitUntil { vault.gate.prompt != nil })
        vault.gate.cancel()
        await refused.value
        #expect(fake.tokens.isEmpty)
        #expect(try await service.passkeys(rpID: "example.com", allowed: []).isEmpty)

        check.answer = true
        await model.importNow()
        #expect(fake.tokens.count == 1)
        guard case .finished(let summary) = model.state else {
            Issue.record("The import did not finish: \(model.state)")
            return
        }
        #expect(summary.hasPrefix("Imported 1 login, 1 with a passkey."))
        #expect(!summary.contains("ada") && !summary.contains("example.com"))
        let id = try #require(try await service.passkeys(rpID: "example.com", allowed: []).first?.id)
        #expect(try await service.reveal(id: id, field: "password") == "synthetic-pw")
    }

    func importCancelled() async throws {
        let (model, _, _, fake) = await setUp()
        fake.importError = CancellationError()
        model.receive(token: UUID())
        await model.importNow()
        #expect(model.state == .idle)
    }

    func exportHandsOver() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (model, _, service, fake) = await setUp(check: check)
        let created = try await addPasskey(service)
        await model.export()
        #expect(check.calls == 1)
        #expect(fake.requests == 1)
        let data = try #require(fake.exported.first)
        let passkeys = data.accounts.flatMap(\.items).flatMap(\.credentials).compactMap { credential -> Data? in
            if case .passkey(let passkey) = credential { return passkey.credentialID }
            return nil
        }
        #expect(passkeys == [created.credentialID])
        guard case .finished = model.state else {
            Issue.record("The export did not finish: \(model.state)")
            return
        }
    }

    func exportSurvivesALockDuringThePick() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (model, vault, service, fake) = await setUp(check: check)
        let created = try await addPasskey(service)
        fake.duringRequest = { await vault.lock() }
        await model.export()
        // Locked during the pick: nothing was read or handed over, and the owner can go on.
        #expect(model.state == .exportPaused)
        #expect(fake.exported.isEmpty && fake.requests == 1)
        #expect(check.calls == 1)
        #expect(!model.canResumeExport)
        await model.resumeExport()
        #expect(model.state == .exportPaused && check.calls == 1 && fake.exported.isEmpty)

        // Unlocked again: the owner check runs again before the keys are read.
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        check.answer = false
        #expect(model.canResumeExport)
        let refused = Task { await model.resumeExport() }
        #expect(await waitUntil { vault.gate.prompt != nil })
        vault.gate.cancel()
        await refused.value
        #expect(model.state == .exportPaused && fake.exported.isEmpty)

        check.answer = true
        await model.resumeExport()
        #expect(fake.requests == 1)  // the sheet does not open again
        let passkeys = fake.exported.flatMap(\.accounts).flatMap(\.items).flatMap(\.credentials).compactMap { credential -> Data? in
            if case .passkey(let passkey) = credential { return passkey.credentialID }
            return nil
        }
        #expect(passkeys == [created.credentialID])
        guard case .finished = model.state else {
            Issue.record("The export did not finish: \(model.state)")
            return
        }
    }

    /// Another vault, selected and opened while the owner is away from the screen.
    private func openAnotherVault(_ vault: VaultModel, _ service: PreviewVaultService) async throws -> VaultEntry {
        let other = try await service.createLocalVault(name: "Other", passphrase: "other synthetic phrase")
        await vault.lock()
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        #expect(vault.isUnlocked && vault.vault?.id == other.id)
        return other
    }

    private func credentialIDs(_ fake: FakeExchange) -> [Data] {
        fake.exported.flatMap(\.accounts).flatMap(\.items).flatMap(\.credentials).compactMap { credential -> Data? in
            if case .passkey(let passkey) = credential { return passkey.credentialID }
            return nil
        }
    }

    func exportDoesNotFollowAnotherVaultOpenedDuringThePick() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (model, vault, service, fake) = await setUp(check: check)
        let original = try #require(vault.vault?.id)
        let created = try await addPasskey(service)
        fake.duringRequest = { [self] in _ = try? await openAnotherVault(vault, service) }
        await model.export()
        // The other vault is open and unlocked, but the export is not its own: nothing is read.
        #expect(model.state == .exportPaused)
        #expect(fake.exported.isEmpty && fake.requests == 1 && check.calls == 1)
        #expect(!model.canResumeExport && model.exportWaitsForAnotherVault)
        await model.resumeExport()
        #expect(model.state == .exportPaused && fake.exported.isEmpty && check.calls == 1)

        // The owner opens the first vault again. A new owner check runs, and then the data goes.
        await vault.select(vaultID: original)
        #expect(!model.canResumeExport)  // locked by the switch
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        #expect(model.canResumeExport && !model.exportWaitsForAnotherVault)
        await model.resumeExport()
        #expect(check.calls == 2 && fake.requests == 1)
        #expect(credentialIDs(fake) == [created.credentialID])
        guard case .finished = model.state else {
            Issue.record("The export did not finish: \(model.state)")
            return
        }
        #expect(!model.canResumeExport)
    }

    func exportWaitsForItsOwnVault() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (model, vault, service, fake) = await setUp(check: check)
        let original = try #require(vault.vault?.id)
        let created = try await addPasskey(service)
        fake.duringRequest = { await vault.lock() }
        await model.export()
        #expect(model.state == .exportPaused && fake.exported.isEmpty && check.calls == 1)

        // During the wait the owner opens another vault: it can neither continue nor take the export.
        _ = try await openAnotherVault(vault, service)
        #expect(!model.canResumeExport && model.exportWaitsForAnotherVault)
        await model.resumeExport()
        #expect(model.state == .exportPaused && fake.exported.isEmpty && check.calls == 1)

        // Back in the first vault: the owner check is new, and a refusal keeps the export waiting.
        await vault.select(vaultID: original)
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        #expect(model.canResumeExport)
        check.answer = false
        let refused = Task { await model.resumeExport() }
        #expect(await waitUntil { vault.gate.prompt != nil })
        vault.gate.cancel()
        await refused.value
        #expect(model.state == .exportPaused && fake.exported.isEmpty)

        check.answer = true
        await vault.select(vaultID: original)
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        await model.resumeExport()
        #expect(fake.requests == 1)
        #expect(credentialIDs(fake) == [created.credentialID])
        guard case .finished = model.state else {
            Issue.record("The export did not finish: \(model.state)")
            return
        }
    }

    func aCanceledPausedExportIsGone() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (model, vault, service, fake) = await setUp(check: check)
        _ = try await addPasskey(service)
        fake.duringRequest = { await vault.lock() }
        await model.export()
        #expect(model.state == .exportPaused)
        model.cancelPausedExport()
        #expect(model.state == .idle)
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        #expect(!model.canResumeExport && !model.exportWaitsForAnotherVault)
        await model.resumeExport()
        #expect(model.state == .idle && fake.exported.isEmpty && check.calls == 1)
    }

    func exportCancelled() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (model, _, _, fake) = await setUp(check: check)
        fake.requestError = ASAuthorizationError(.canceled)
        await model.export()
        #expect(fake.exported.isEmpty)
        #expect(model.state == .idle)
    }
}
