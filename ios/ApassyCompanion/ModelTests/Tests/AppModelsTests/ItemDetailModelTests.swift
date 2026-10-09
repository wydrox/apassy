import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("ItemDetailModel")
struct ItemDetailModelTests {
    private let password = "synthetic-Pw-7Hq2!kLm9x"

    /// An unlocked preview vault with a detail model of an item.
    private func makeDetail(
        id: UInt64 = 100, check: ScriptedOwnerCheck = ScriptedOwnerCheck(),
        lifetime: Duration = .milliseconds(80)
    ) async -> (ItemDetailModel, VaultModel) {
        let (vault, _) = makeVault(service: PreviewVaultService(empty: false, unlocked: true), check: check)
        await vault.start()
        vault.stopSync()
        let detail = ItemDetailModel(id: id, vault: vault, revealLifetime: lifetime)
        await detail.load()
        return (detail, vault)
    }

    private func field(_ detail: ItemDetailModel, _ name: String) throws -> FieldView {
        try #require(detail.detail?.fields.first { $0.name == name })
    }

    private func totpField(_ detail: ItemDetailModel) throws -> FieldView {
        try #require(detail.detail?.field(.totp))
    }

    @Test("load reads the four fields of an item")
    func load() async {
        let (detail, _) = await makeDetail()
        #expect(detail.detail?.fields.count == 4)
        #expect(detail.title == "GitHub")
        #expect(!detail.isGone)
        #expect(detail.loadError == nil)
    }

    @Test("an item that is not in the vault is gone")
    func gone() async {
        let (detail, _) = await makeDetail(id: 9999)
        #expect(detail.isGone)
        #expect(detail.detail == nil)
    }

    @Test("a revealed secret shows after the owner check and goes after its lifetime")
    func revealExpires() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (detail, _) = await makeDetail(check: check)
        let field = try field(detail, "password")
        await detail.reveal(field)
        #expect(detail.revealed["password"] == password)
        #expect(detail.isRevealed(field))
        #expect(check.reasons == ["Show the password of “GitHub”"])
        #expect(await waitUntil(seconds: 1) { detail.revealed["password"] == nil })
    }

    @Test("a cancelled passphrase prompt reveals nothing")
    func revealCancelled() async throws {
        let check = ScriptedOwnerCheck(answer: false)
        let (detail, vault) = await makeDetail(check: check)
        let field = try field(detail, "password")
        let task = Task { await detail.reveal(field) }
        #expect(await waitUntil { vault.gate.prompt != nil })
        vault.gate.cancel()
        await task.value
        #expect(detail.revealed.isEmpty)
        #expect(detail.working.isEmpty)
    }

    @Test("hide removes a revealed secret at once")
    func hide() async throws {
        let (detail, _) = await makeDetail(lifetime: .seconds(30))
        let field = try field(detail, "password")
        await detail.reveal(field)
        #expect(detail.isRevealed(field))
        detail.hide(field)
        #expect(!detail.isRevealed(field))
    }

    @Test("dropSecrets clears the revealed values, the codes, and a secret in large type")
    func dropSecrets() async throws {
        let (detail, _) = await makeDetail(lifetime: .seconds(30))
        await detail.reveal(try field(detail, "password"))
        await detail.showCode(try totpField(detail))
        await detail.showLargeType(try field(detail, "password"))
        #expect(!detail.revealed.isEmpty)
        #expect(!detail.codes.isEmpty)
        #expect(detail.largeType != nil)

        detail.dropSecrets()
        #expect(detail.revealed.isEmpty)
        #expect(detail.codes.isEmpty)
        #expect(detail.largeType == nil)
    }

    @Test("a one-time code shows as six digits after the owner check")
    func showCode() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (detail, _) = await makeDetail(check: check)
        let field = try totpField(detail)
        await detail.showCode(field)
        let code = try #require(detail.codes[field.name]).code
        #expect(code.code.count == 6)
        #expect(code.code.allSatisfy { $0.isASCII && $0.isNumber })
        #expect(check.calls == 1)
        detail.hideCode(field)
        #expect(detail.codes.isEmpty)
    }

    @Test("a field that is not a one-time password shows no code")
    func showCodeWrongRole() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (detail, _) = await makeDetail(check: check)
        await detail.showCode(try field(detail, "password"))
        #expect(detail.codes.isEmpty)
        #expect(check.calls == 0)
    }

    @Test("large type of a plain field needs no owner check")
    func largeTypePlain() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (detail, _) = await makeDetail(check: check)
        await detail.showLargeType(try field(detail, "username"))
        #expect(check.calls == 0)
        #expect(detail.largeType?.value == "octocat")
        #expect(detail.largeType?.secret == false)
        detail.closeLargeType()
        #expect(detail.largeType == nil)
    }

    @Test("large type of a secret needs the owner check and is marked secret")
    func largeTypeSecret() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (detail, _) = await makeDetail(check: check)
        await detail.showLargeType(try field(detail, "password"))
        #expect(check.calls == 1)
        #expect(detail.largeType?.secret == true)
        #expect(detail.largeType?.value == password)
        #expect(await waitUntil(seconds: 1) { detail.largeType == nil })
    }

    @Test("delete removes the item from the vault")
    func delete() async {
        let (detail, vault) = await makeDetail()
        #expect(vault.item(100) != nil)
        #expect(await detail.delete())
        #expect(vault.item(100) == nil)
    }

    @Test("a favorite is toggled from the item")
    func favorite() async {
        let (detail, _) = await makeDetail()
        #expect(!detail.isFavorite)
        detail.toggleFavorite()
        #expect(detail.isFavorite)
    }
}
