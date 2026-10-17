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
        #expect(
            editor.draft().fields == [.named("username", "u", secret: false), .named("password", "p", secret: true)])
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
        #expect(editor.error == "Enter a name.")
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
        #expect(editor.error != "Enter a name.")
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
        #expect(
            try await service.reveal(id: 100, field: otpName) == "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP"
        )
    }

    @Test("a stored hidden detail keeps its value under its stored name, also when renamed")
    func storedHiddenDetail() {
        let row = ItemRow(
            id: 7, revision: 2, title: "Bank", kind: .login, subtitle: "me", websites: [], tags: [], archived: false,
            hasTotp: false, conflictOf: nil, addedAt: nil, changedAt: nil, usedAt: nil)
        let detail = ItemDetail(
            row: row, notes: "",
            fields: [
                FieldView(
                    name: "username", label: "Username", secret: false, value: "me", role: .username, custom: false),
                FieldView(
                    name: "password", label: "Password", secret: true, value: nil, role: .password, custom: false),
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

@MainActor
@Suite("ItemEditor submission safety")
struct ItemEditorSubmissionTests {
    private func login(folder: String? = nil) -> ItemEditorModel {
        let editor = ItemEditorModel(kind: .login, folder: folder)
        editor.title = "Synthetic account"
        editor.values["username"] = "first@example.test"
        editor.values["password"] = "synthetic-password"
        return editor
    }

    @Test("dirty protection includes pending input and exact changes can be undone")
    func dirtyDraft() async throws {
        let editor = ItemEditorModel(kind: .login, folder: PreviewOrganize.FolderID.billing)
        #expect(!editor.hasChanges)
        #expect(!editor.preventsDismissal)
        editor.pendingTag = "work"
        #expect(editor.hasChanges)
        #expect(editor.preventsDismissal)
        editor.pendingTag = ""
        #expect(!editor.hasChanges)
        editor.addDetail()
        #expect(editor.hasChanges)
        editor.removeDetails(at: [0])
        #expect(!editor.hasChanges)

        let service = PreviewVaultService(unlocked: true)
        let existing = ItemEditorModel(detail: try await service.item(id: 100))
        #expect(!existing.hasChanges)
        existing.title += " changed"
        #expect(existing.hasChanges)
        existing.title = "GitHub"
        #expect(!existing.hasChanges)
        existing.values["password"] = "replacement"
        #expect(existing.hasChanges)
    }

    @Test("Save commits a typed tag without Return and rejects invalid pending tags without a write")
    func pendingTag() async throws {
        let service = SpyVaultService(organize: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let editor = login()
        editor.pendingTag = "  work  "
        let saved = try #require(await editor.save(in: vault))
        #expect(vault.item(saved.id)?.tags == ["work"])
        #expect(editor.pendingTag.isEmpty)
        #expect(editor.tags == ["work"])

        let invalid = login()
        invalid.pendingTag = String(repeating: "a", count: 65)
        #expect(await invalid.save(in: vault) == nil)
        #expect(invalid.pendingTag == String(repeating: "a", count: 65))
        #expect(invalid.error == "Use a shorter tag.")
        #expect(await service.saveCalls.count == 1)
    }

    @Test("a suspended save submits its original fields and destination once")
    func stableSubmission() async throws {
        let service = SpyVaultService(organize: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let gate = VaultCallGate()
        await service.setSaveHook { await gate.wait() }
        defer { gate.release() }
        let billing = PreviewOrganize.FolderID.billing
        let editor = login(folder: billing)
        editor.pendingTag = "submitted"
        let task = Task { await editor.save(in: vault) }
        #expect(await waitUntil { gate.isWaiting })
        #expect(editor.isSaving)
        #expect(editor.preventsDismissal)
        #expect(await editor.save(in: vault) == nil)
        // Bypass the disabled UI deliberately: even an external mutation cannot redirect this save.
        editor.title = "Later title"
        editor.values["username"] = "later@example.test"
        editor.folder = PreviewOrganize.FolderID.personal
        gate.release()
        let saved = try #require(await task.value)
        let detail = try await service.item(id: saved.id)
        #expect(detail.row.title == "Synthetic account")
        #expect(detail.row.subtitle == "first@example.test")
        #expect(detail.row.folder == billing)
        #expect(detail.row.tags == ["submitted"])
        #expect(editor.savedTitle == "Synthetic account")
        #expect(editor.savedFolder == billing)
        #expect(!editor.isSaving)
        #expect(await service.saveCalls.count == 1)
    }

    @Test("a failed write preserves draft fields, tags, destination and the actionable error")
    func failedWriteRetainsDraft() async {
        let service = SpyVaultService(organize: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        await service.setSaveHook { throw VaultError(.io, "Could not write the synthetic file. Retry Save.") }
        let editor = login(folder: PreviewOrganize.FolderID.billing)
        editor.pendingTag = "keep"
        let before = vault.items.count
        #expect(await editor.save(in: vault) == nil)
        #expect(editor.error == "Could not write the synthetic file. Retry Save.")
        #expect(editor.title == "Synthetic account")
        #expect(editor.values["password"] == "synthetic-password")
        #expect(editor.tags == ["keep"])
        #expect(editor.folder == PreviewOrganize.FolderID.billing)
        #expect(editor.hasChanges)
        #expect(!editor.isSaving)
        #expect(vault.items.count == before)
    }

    @Test("all ordinary login requirements are visible before Save; Website remains optional")
    func visibleRequirements() {
        let editor = ItemEditorModel(kind: .login)
        #expect(editor.validationMessages == ["Enter a name.", "Enter username.", "Enter password."])
        editor.title = "Synthetic login"
        editor.values["username"] = "account@example.test"
        editor.values["password"] = "synthetic-password"
        #expect(editor.validationMessages.isEmpty)
        #expect(editor.website.isEmpty)
    }

    @Test("a new item never silently loses a destination deleted before the editor loads")
    func missingInitialDestination() async throws {
        let service = SpyVaultService(organize: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let editor = login(folder: "missing-synthetic-folder")
        await editor.loadFolders(from: service)
        #expect(editor.folder == "missing-synthetic-folder")
        #expect(editor.validationMessages.contains("Choose an available folder."))
        #expect(await editor.save(in: vault) == nil)
        #expect(await service.saveCalls.isEmpty)
    }

    @Test("changes after a failed move update the saved identity instead of creating another item")
    func changedPartialSaveRetry() async throws {
        let service = SpyVaultService(organize: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let personal = PreviewOrganize.FolderID.personal
        let editor = login(folder: personal)
        await editor.loadFolders(from: service)
        _ = try await service.deleteFolder(uuid: personal)
        let before = vault.items.count
        #expect(await editor.save(in: vault) == nil)
        let partial = try #require(editor.savedItem)
        editor.title = "Corrected name"
        editor.folder = nil
        let retried = try #require(await editor.save(in: vault))
        #expect(retried.id == partial.id)
        #expect(retried.revision == partial.revision + 1)
        #expect(vault.item(retried.id)?.title == "Corrected name")
        #expect(vault.items.count == before + 1)
        let calls = await service.saveCalls
        #expect(calls.count == 2)
        #expect(calls[0].id == nil)
        #expect(calls[1].id == partial.id)
        #expect(calls[1].revision == partial.revision)
    }

    @Test(
        "leaving a partial save reports its persisted identity and actual location, not later edits",
        arguments: [false, true])
    func reportPartialSavedResult(editingExisting: Bool) async throws {
        let service = SpyVaultService(organize: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let personal = PreviewOrganize.FolderID.personal
        let editor: ItemEditorModel
        if editingExisting {
            editor = ItemEditorModel(detail: try await service.item(id: 100))
            editor.folder = personal
        } else {
            editor = login(folder: personal)
        }
        var reported: [(id: UInt64, title: String)] = []
        var reportedFolder: String? = "not-reported"
        #expect(
            !editor.reportSavedResult { items, folder in
                reported = items
                reportedFolder = folder
            })
        #expect(reported.isEmpty)
        #expect(reportedFolder == "not-reported")

        await editor.loadFolders(from: service)
        _ = try await service.deleteFolder(uuid: personal)
        #expect(await editor.save(in: vault) == nil)
        let partial = try #require(editor.savedItem)
        let retained = try await service.item(id: partial.id)
        #expect(editor.moveFailure != nil)
        // These are unsaved choices. Explicit Close Editor must reveal the retained version.
        editor.title = "Unsaved later name"
        editor.folder = PreviewOrganize.FolderID.billing
        #expect(
            editor.reportSavedResult { items, folder in
                reported = items
                reportedFolder = folder
            })
        #expect(reported.map(\.id) == [partial.id])
        #expect(reported.map(\.title) == [retained.row.title])
        #expect(reportedFolder == retained.row.folder)
        #expect(reportedFolder == (editingExisting ? PreviewOrganize.FolderID.acme : nil))
        #expect(reportedFolder != personal)
        #expect(reportedFolder != editor.folder)
        #expect(await service.saveCalls.count == 1)
        #expect(editor.moveFailure != nil)
    }

    @Test("an older core without folder capability clears inherited destination without a dirty edit")
    func noFolderCapability() async throws {
        let service = SpyVaultService.olderCore()
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let editor = ItemEditorModel(kind: .login, folder: PreviewOrganize.FolderID.billing)
        await editor.loadFolders(from: service)
        #expect(editor.folders.isEmpty)
        #expect(editor.folder == nil)
        #expect(!editor.hasChanges)
        #expect(!editor.preventsDismissal)
        editor.title = "Older core login"
        editor.values["username"] = "synthetic@example.test"
        editor.values["password"] = "synthetic-password"
        let saved = try #require(await editor.save(in: vault))
        #expect(vault.item(saved.id) != nil)
        #expect(editor.moveFailure == nil)
        #expect(await service.saveCalls.count == 1)
    }
}
