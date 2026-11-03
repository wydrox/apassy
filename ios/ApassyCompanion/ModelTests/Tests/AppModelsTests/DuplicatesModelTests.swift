import ApassyVaultKit
import AuthenticationServices
import Foundation
import Testing

@testable import AppModels

// "Find duplicates": the screen model over the preview vault, and the offer after an import. The
// values are synthetic.

@MainActor
@Suite("Duplicates")
struct DuplicatesModelTests {
    private func unlockedVault(check: ScriptedOwnerCheck = ScriptedOwnerCheck()) async -> (VaultModel, PreviewVaultService) {
        let service = PreviewVaultService(empty: false, unlocked: true)
        let (vault, _) = makeVault(service: service, check: check)
        await vault.start()
        vault.stopSync()
        return (vault, service)
    }

    /// Two API keys of the same synthetic token: an identical group.
    private func identicalPair(_ service: PreviewVaultService, token: String) async throws -> (SavedItem, SavedItem) {
        let draft = ItemDraft(
            title: "Synthetic key", kind: .apiKey, notes: "", tags: [],
            fields: [.named("token", token, secret: true)])
        let a = try await service.save(id: nil, revision: nil, draft: draft)
        let b = try await service.save(id: nil, revision: nil, draft: draft)
        return (a, b)
    }

    private func group(_ model: DuplicatesModel, containing id: UInt64) -> DuplicateGroup? {
        model.groups.first { $0.items.contains { $0.id == id } }
    }

    @Test("the screen lists the groups of the vault")
    func loads() async throws {
        let (vault, service) = await unlockedVault()
        let (a, b) = try await identicalPair(service, token: "synthetic-token-1")
        let model = DuplicatesModel(vault: vault)
        #expect(model.phase == .loading)
        await model.load()
        #expect(model.phase == .loaded)
        let found = try #require(group(model, containing: a.id))
        #expect(Set(found.items.map(\.id)) == [a.id, b.id])
        #expect(found.differenceSummary == "Same values")
        #expect(model.identicalGroups.contains { $0.id == found.id })
        #expect(model.keepID(for: found) == found.keep)
    }

    @Test("an older service shows its message")
    func olderService() async {
        let spy = SpyVaultService()
        let (vault, _) = makeVault(service: spy)
        await vault.start()
        vault.stopSync()
        let model = DuplicatesModel(vault: vault)
        await model.load()
        guard case .failed(let message) = model.phase else {
            Issue.record("The screen did not fail: \(model.phase)")
            return
        }
        #expect(message.contains("Update Apassy"))
    }

    @Test("a merge asks the owner, keeps the chosen item, and archives the others")
    func mergeAsksTheOwner() async throws {
        let check = ScriptedOwnerCheck(answer: false)
        let (vault, service) = await unlockedVault(check: check)
        let (a, b) = try await identicalPair(service, token: "synthetic-token-2")
        let model = DuplicatesModel(vault: vault)
        await model.load()
        let found = try #require(group(model, containing: a.id))
        model.choose(b.id, for: found)
        #expect(model.keepID(for: found) == b.id)
        #expect(model.confirmationTitle(for: found) == "Merge 2 items into “Synthetic key”?")

        // The owner says no: nothing changes.
        let refused = Task { await model.merge(found) }
        #expect(await waitUntil { vault.gate.prompt != nil })
        vault.gate.cancel()
        #expect(await refused.value == nil)
        #expect(try await service.item(id: a.id).row.archived == false)

        check.answer = true
        let kept = await model.merge(found)
        #expect(kept?.id == b.id)
        #expect(check.reasons.allSatisfy { $0 == DuplicatesModel.ownerReason })
        #expect(try await service.item(id: a.id).row.archived)
        #expect(try await service.item(id: b.id).row.archived == false)
        #expect(vault.item(a.id)?.archived == true)
        #expect(group(model, containing: b.id) == nil)
        #expect(model.alert == nil)
        #expect(!model.isMerging)
    }

    @Test("a group that changed after it was read reloads and says so")
    func conflictReloads() async throws {
        let (vault, service) = await unlockedVault()
        let (a, b) = try await identicalPair(service, token: "synthetic-token-3")
        let model = DuplicatesModel(vault: vault)
        await model.load()
        let found = try #require(group(model, containing: a.id))
        // Another device changes one item: its revision moves on.
        _ = try await service.save(
            id: b.id, revision: b.revision,
            draft: ItemDraft(
                title: "Synthetic key", kind: .apiKey, notes: "synthetic note", tags: [],
                fields: [.named("token", nil, secret: true)]))

        #expect(await model.merge(found) == nil)
        #expect(model.alert == DuplicatesModel.changedMessage)
        #expect(try await service.item(id: a.id).row.archived == false)
        // The list was read again, with the new revision and the new difference.
        let fresh = try #require(group(model, containing: a.id))
        #expect(fresh.member(b.id)?.revision == b.revision + 1)
        #expect(fresh.differences == ["Notes"])
    }

    @Test("when a member has a passkey, only that member can be kept")
    func passkeyMemberIsKept() async throws {
        let (vault, service) = await unlockedVault()
        let passkey = try await service.passkeyRegister(
            PasskeyRegistration(
                rpID: "example.com", userName: "ada", userDisplayName: "Ada", userHandle: Data([1, 2]),
                clientDataHash: Data(repeating: 3, count: 32), algorithms: [-7], excluded: [], attach: nil,
                title: "Example"))
        let other = try await service.save(
            id: nil, revision: nil,
            draft: ItemDraft(
                title: "Example (imported)", kind: .login, notes: "", tags: [],
                fields: [
                    .named("username", "ada", secret: false), .named("password", "synthetic-pw", secret: true),
                    .detail("Website", "https://example.com", secret: false),
                ]))
        let model = DuplicatesModel(vault: vault)
        await model.load()
        let found = try #require(group(model, containing: passkey.id))
        #expect(!model.canChoose(in: found))
        model.choose(other.id, for: found)
        #expect(model.keepID(for: found) == passkey.id)
        #expect(await model.merge(found)?.id == passkey.id)
        #expect(try await service.item(id: other.id).row.archived)
        #expect(try await service.item(id: passkey.id).passkey != nil)
    }

    @Test("merge all identical merges each identical group with one owner check")
    func mergeAllIdentical() async throws {
        let check = ScriptedOwnerCheck()
        let (vault, service) = await unlockedVault(check: check)
        let (a, _) = try await identicalPair(service, token: "synthetic-token-4")
        let (c, _) = try await identicalPair(service, token: "synthetic-token-5")
        let model = DuplicatesModel(vault: vault)
        await model.load()
        let identical = model.identicalGroups.count
        #expect(identical >= 2)
        let differing = model.groups.filter { !$0.identical }.count
        #expect(await model.mergeAllIdentical() == identical)
        #expect(check.calls == 1)
        #expect(group(model, containing: a.id) == nil)
        #expect(group(model, containing: c.id) == nil)
        #expect(model.identicalGroups.isEmpty)
        // A group whose values differ waits for the owner.
        #expect(model.groups.count == differing)
    }

    @Test("an import that finished offers the duplicates, and closing it drops the offer")
    func importOffersDuplicates() async throws {
        guard #available(macOS 26.0, *) else { return }
        try await DuplicatesImportCase().importOffersDuplicates()
    }
}

/// Swift Testing takes no `@available` test: the test above checks the OS and runs this case.
@available(macOS 26.0, *)
@MainActor
private struct DuplicatesImportCase {
    func importOffersDuplicates() async throws {
        let service = PreviewVaultService(empty: false, unlocked: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        vault.stopSync()
        let item = ASImportableItem(
            id: Data([1]), created: Date(), lastModified: Date(), title: "Example",
            credentials: [
                .basicAuthentication(.init(
                    userName: ASImportableEditableField(id: nil, fieldType: .string, value: "ada"),
                    password: ASImportableEditableField(id: nil, fieldType: .concealedString, value: "synthetic-pw")))
            ])
        let data = ASExportedCredentialData(
            accounts: [ASImportableAccount(id: Data([1]), userName: "", email: "", collections: [], items: [item])],
            formatVersion: .v1, exporterRelyingPartyIdentifier: "exporter.example", exporterDisplayName: "Exporter",
            timestamp: Date())
        let model = CredentialExchangeModel(
            vault: vault,
            system: CredentialExchangeModel.System(
                importCredentials: { _ in data },
                requestExport: { throw CancellationError() },
                exportCredentials: { _ in }))
        model.receive(token: UUID())
        #expect(model.duplicateGroups == 0)
        await model.importNow()
        guard case .finished = model.state else {
            Issue.record("The import did not finish: \(model.state)")
            return
        }
        // The preview vault has a conflict copy of a login: one group at least.
        let expected = try await vault.service.duplicates().count
        #expect(expected > 0)
        #expect(model.duplicateGroups == expected)
        model.dismiss()
        #expect(model.duplicateGroups == 0)
    }
}
