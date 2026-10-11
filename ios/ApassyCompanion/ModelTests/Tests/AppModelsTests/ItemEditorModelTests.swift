import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("ItemEditorModel")
struct ItemEditorModelTests {
    private func detail(_ id: UInt64, in service: PreviewVaultService) async throws -> ItemDetail {
        try await service.item(id: id)
    }

    @Test("a new login makes a draft with its website and one-time password as details")
    func newLoginDraft() {
        let editor = ItemEditorModel(kind: .login)
        editor.title = "  Example  "
        editor.values["username"] = "u"
        editor.values["password"] = "p"
        editor.website = "https://x.org"
        editor.otp = "JBSWY3DPEHPK3PXP"
        let draft = editor.draft()
        #expect(draft.title == "Example")
        #expect(draft.kind == .login)
        #expect(
            draft.fields == [
                .named("username", "u", secret: false),
                .named("password", "p", secret: true),
                .detail("Website", "https://x.org", secret: false),
                .detail("One-time password", "JBSWY3DPEHPK3PXP", secret: true),
            ])
    }

    @Test("an empty website and an empty one-time password are left out")
    func emptyOptional() {
        let editor = ItemEditorModel(kind: .login)
        editor.values["username"] = "u"
        editor.values["password"] = "p"
        editor.website = "  "
        #expect(editor.draft().fields == [.named("username", "u", secret: false), .named("password", "p", secret: true)])
    }

    @Test("editing a login keeps its website, and its secrets stay unchanged")
    func editLogin() async throws {
        let service = PreviewVaultService(unlocked: true)
        let editor = ItemEditorModel(detail: try await detail(100, in: service))
        #expect(!editor.isNew)
        #expect(editor.title == "GitHub")
        #expect(editor.website == "https://github.com")
        #expect(editor.otpStored)
        #expect(editor.isUnchanged("password"))
        #expect(
            editor.draft().fields == [
                .named("username", "octocat", secret: false),
                .named("password", nil, secret: true),
                .detail("Website", "https://github.com", secret: false),
                .detail("One-time password", nil, secret: true),
            ])

        editor.values["password"] = "new"
        #expect(!editor.isUnchanged("password"))
        #expect(editor.draft().fields.contains(.named("password", "new", secret: true)))
    }

    @Test("a website that is stored under the label url keeps that label")
    func editWebsiteLabel() async throws {
        let service = PreviewVaultService(unlocked: true)
        let editor = ItemEditorModel(detail: try await detail(105, in: service))
        #expect(editor.website == "netflix.com")
        #expect(editor.draft().fields.contains(.detail("url", "netflix.com", secret: false)))
    }

    @Test("an item of the other kind keeps the name of its secret and its value")
    func editCustom() async throws {
        let service = PreviewVaultService(unlocked: true)
        let editor = ItemEditorModel(detail: try await detail(106, in: service))
        #expect(editor.kind == .custom)
        #expect(editor.customName == "wifi_password")
        #expect(editor.draft().fields.first == .named("wifi_password", nil, secret: true))
    }

    @Test("a tag that the item has, in other case, is refused with a message")
    func duplicateTag() async throws {
        let service = PreviewVaultService(unlocked: true)
        let editor = ItemEditorModel(detail: try await detail(100, in: service))
        #expect(editor.tags == ["work"])
        #expect(!editor.addTag("WORK"))
        #expect(editor.tagMessage == "The item has this tag.")
        #expect(editor.tags == ["work"])
        #expect(editor.addTag("  home "))
        #expect(editor.tagMessage == nil)
        #expect(editor.tags == ["work", "home"])
        editor.removeTag("work")
        #expect(editor.tags == ["home"])
    }

    @Test("a tag has at most 64 bytes, and an item has at most 32 tags")
    func tagLimits() {
        let editor = ItemEditorModel(kind: .login)
        #expect(!editor.addTag(String(repeating: "a", count: 65)))
        #expect(editor.tagMessage == "Use a shorter tag.")
        for index in 0..<32 { #expect(editor.addTag("tag \(index)")) }
        #expect(!editor.addTag("one more"))
        #expect(editor.tagMessage == "An item has at most 32 tags.")
    }

    @Test("an item has at most ten details")
    func detailLimit() {
        let editor = ItemEditorModel(kind: .login)
        for _ in 0..<9 { editor.addDetail() }
        #expect(editor.canAddDetail)
        editor.addDetail()
        #expect(editor.details.count == 10)
        #expect(!editor.canAddDetail)
        editor.addDetail()
        #expect(editor.details.count == 10)
    }

    @Test("the website and the code count as details")
    func detailCount() {
        let editor = ItemEditorModel(kind: .login)
        editor.website = "x.org"
        editor.otp = "JBSWY3DPEHPK3PXP"
        for _ in 0..<8 { editor.addDetail() }
        #expect(editor.detailCount == 10)
        #expect(!editor.canAddDetail)
    }

    @Test("saving with no title shows a message and sends nothing")
    func saveWithoutTitle() async {
        let (vault, _) = makeVault(service: PreviewVaultService(unlocked: true))
        await vault.start()
        defer { vault.stopSync() }
        let editor = ItemEditorModel(kind: .login)
        editor.title = "   "
        #expect(await editor.save(in: vault) == nil)
        #expect(editor.error == "Type a title.")
        #expect(vault.items.count == 9)
    }

    @Test("saving a new item adds it to the vault")
    func saveNew() async throws {
        let (vault, _) = makeVault(service: PreviewVaultService(unlocked: true))
        await vault.start()
        defer { vault.stopSync() }
        let editor = ItemEditorModel(kind: .login)
        editor.title = "Example"
        editor.values["username"] = "u"
        editor.values["password"] = "p"
        let saved = try #require(await editor.save(in: vault))
        #expect(vault.item(saved.id)?.title == "Example")
        #expect(editor.error == nil)
    }

    @Test("the message of the core shows when a save fails")
    func saveFails() async {
        let (vault, _) = makeVault(service: PreviewVaultService(unlocked: true))
        await vault.start()
        defer { vault.stopSync() }
        let editor = ItemEditorModel(kind: .login)
        editor.title = "Example"
        #expect(await editor.save(in: vault) == nil)
        #expect(editor.error != nil)
        #expect(editor.error != "Type a title.")
    }

    @Test("editing the title of an item keeps its password")
    func editKeepsPassword() async throws {
        let service = PreviewVaultService(unlocked: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let editor = ItemEditorModel(detail: try await detail(100, in: service))
        editor.title = "GitHub personal"
        let saved = try #require(await editor.save(in: vault))
        #expect(saved.id == 100)
        #expect(vault.item(100)?.title == "GitHub personal")
        #expect(try await service.reveal(id: 100, field: "password") == "synthetic-Pw-7Hq2!kLm9x")
        let otpName = "x_4f6e652d74696d652070617373776f7264"
        #expect(try await service.reveal(id: 100, field: otpName) == "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP")
    }

    @Test("a stored hidden detail keeps its value under its stored name, also when renamed")
    func storedHiddenDetail() {
        let row = ItemRow(
            id: 7, revision: 2, title: "Bank", kind: .login, subtitle: "me", websites: [], tags: [], archived: false,
            hasTotp: false, conflictOf: nil, addedAt: nil, changedAt: nil, usedAt: nil)
        let detail = ItemDetail(
            row: row, notes: "",
            fields: [
                FieldView(name: "username", label: "Username", secret: false, value: "me", role: .username, custom: false),
                FieldView(name: "password", label: "Password", secret: true, value: nil, role: .password, custom: false),
                FieldView(name: "x_50494e", label: "PIN", secret: true, value: nil, role: .other, custom: true),
            ])
        let editor = ItemEditorModel(detail: detail)
        #expect(editor.details.count == 1)
        #expect(editor.details[0].stored)
        editor.details[0].label = "Card PIN"
        #expect(editor.draft().fields.last == DraftField(name: "x_50494e", label: "Card PIN", value: nil, secret: true))
        editor.details[0].value = "1234"
        #expect(editor.draft().fields.last == .detail("Card PIN", "1234", secret: true))
    }
}
