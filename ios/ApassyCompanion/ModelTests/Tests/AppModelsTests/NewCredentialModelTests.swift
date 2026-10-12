import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// Synthetic pastes that the preview vault detects. No value is real.
private enum Paste {
    static let stripe = "sk_test_EXAMPLE00000000000000000000"
    static let env = """
        STRIPE_SECRET_KEY=sk_test_EXAMPLE00000000000000000000
        GITHUB_TOKEN=ghp_EXAMPLE000000000000000000000000000000
        DATABASE_URL=postgres://app:EXAMPLE-password@db.example.com:5432/app
        """
}

@MainActor
@Suite("NewCredentialModel")
struct NewCredentialModelTests {
    private let billing = PreviewOrganize.FolderID.billing

    private func model(
        _ service: PreviewVaultService = PreviewVaultService(unlocked: true), folder: String? = nil
    ) -> NewCredentialModel {
        NewCredentialModel(service: service, folder: folder, debounce: .milliseconds(40))
    }

    @Test("detection waits until the text stops changing, and only the last text applies")
    func debounce() async {
        let paste = model()
        paste.text = Paste.env
        paste.text = Paste.stripe
        #expect(paste.rows.isEmpty)
        #expect(!paste.isCurrent)
        #expect(!paste.canAdd)
        #expect(await waitUntil { paste.isCurrent })
        #expect(paste.rows.map(\.found.title) == ["Stripe test"])
        #expect(!paste.hasChoices)
        #expect(paste.addLabel == "Add")
        #expect(paste.canAdd)
    }

    @Test("a detected row has the Mac's line, the cap of a signal, and only the core's mask")
    func rowMapping() async throws {
        let paste = model()
        paste.text = Paste.stripe
        await paste.detectNow()
        let row = try #require(paste.rows.first)
        #expect(row.found.rowLine == "Stripe · STRIPE_SECRET_KEY · api.stripe.com")
        #expect(row.found.cap?.label == "Development")
        #expect(row.found.cap?.red == false)
        #expect(row.masked == "sk_test_••••••••")
        #expect(paste.maskedText == "sk_test_••••••••")
        #expect(!paste.maskedText.contains("EXAMPLE"))
        #expect(!row.masked.contains("EXAMPLE"))
    }

    @Test("a .env paste gives one checked row for each line, and masked lines")
    func envRows() async {
        let paste = model()
        paste.text = Paste.env
        await paste.detectNow()
        #expect(paste.rows.count == 3)
        #expect(paste.rows.map(\.found.line) == [1, 2, 3])
        #expect(paste.rows.allSatisfy { $0.keep })
        #expect(paste.hasChoices)
        #expect(paste.addLabel == "Add 3")
        #expect(
            paste.maskedText
                == "STRIPE_SECRET_KEY=sk_test_••••••••\nGITHUB_TOKEN=ghp_••••••••\nDATABASE_URL=••••••••")
        #expect(paste.rows[2].found.cap == nil)
    }

    @Test("an empty paste shows no hint, and Add stays off")
    func emptyPaste() async {
        let paste = model()
        paste.text = "  \n "
        await paste.detectNow()
        #expect(paste.rows.isEmpty)
        #expect(!paste.showsNothingFound)
        #expect(!paste.canAdd)
        #expect(paste.maskedText.isEmpty)
    }

    @Test("a detection error shows the core's message instead of rows")
    func detectError() async {
        let paste = model()
        paste.text = Paste.stripe
        await paste.detectNow()
        #expect(paste.rows.count == 1)
        paste.text = String(repeating: "x", count: 1_048_577)
        await paste.detectNow()
        #expect(paste.rows.isEmpty)
        #expect(paste.detectError != nil)
        #expect(!paste.showsNothingFound)
        #expect(!paste.canAdd)
    }

    @Test("a new detection keeps the titles and checkboxes of the rows that stay")
    func followKeepsChoices() async {
        let paste = model()
        paste.text = Paste.env
        await paste.detectNow()
        paste.setTitle("Billing Stripe", row: 0)
        paste.setKeep(false, row: 1)
        paste.text = Paste.env + "\n"
        await paste.detectNow()
        #expect(paste.rows[0].title == "Billing Stripe")
        #expect(paste.rows[1].keep == false)
        #expect(paste.rows[2].keep)
    }

    @Test("Add sends the checked rows and the typed titles, into the folder, and reloads the vault")
    func addPicksAndTitles() async throws {
        let service = PreviewVaultService(unlocked: true)
        let (vault, recorder) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let before = vault.activeItems.count
        let paste = model(service, folder: billing)
        await paste.loadFolders()
        #expect(paste.folder == billing)
        #expect(paste.folderLabel == "Acme › Billing")
        paste.text = Paste.env
        await paste.detectNow()
        paste.setTitle("  Billing Stripe  ", row: 0)
        paste.setKeep(false, row: 1)
        paste.setTitle("Not added", row: 1)
        #expect(paste.pick == [0, 2])
        #expect(paste.titles == [0: "Billing Stripe"])
        #expect(paste.addLabel == "Add 2")

        let added = try #require(await paste.add(in: vault))
        #expect(added.map(\.title) == ["Billing Stripe", "PostgreSQL database"])
        #expect(paste.error == nil)
        #expect(vault.activeItems.count == before + 2)
        for item in added {
            #expect(vault.item(item.id)?.folder == billing)
        }
        #expect(!vault.activeItems.contains { $0.title == "Not added" })
        #expect(!vault.activeItems.contains { $0.title.hasPrefix("GitHub token") })
        #expect(recorder.replacedIdentities.last == previewVaultID)
        // The paste is gone after Add.
        #expect(paste.text.isEmpty)
        #expect(paste.rows.isEmpty)
    }

    @Test("Add right after a change detects the new text first")
    func addDetectsFirst() async throws {
        let service = PreviewVaultService(unlocked: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let paste = NewCredentialModel(service: service, folder: nil, debounce: .seconds(30))
        paste.text = Paste.stripe
        let added = try #require(await paste.add(in: vault))
        #expect(added.map(\.title) == ["Stripe test"])
        #expect(vault.item(added[0].id)?.folder == nil)
    }

    @Test("with every row unchecked, Add is off and says why")
    func nothingPicked() async {
        let (vault, _) = makeVault(service: PreviewVaultService(unlocked: true))
        await vault.start()
        defer { vault.stopSync() }
        let paste = model()
        paste.text = Paste.env
        await paste.detectNow()
        for row in paste.rows { paste.setKeep(false, row: row.id) }
        #expect(!paste.canAdd)
        #expect(await paste.add(in: vault) == nil)
        #expect(paste.error == "Pick at least one credential.")
        #expect(paste.text == Paste.env)
    }

    @Test("a folder that is gone gives way to the top level")
    func folderDefault() async {
        let none = model()
        await none.loadFolders()
        #expect(none.folder == nil)
        #expect(none.folderLabel == "No folder")
        #expect(none.folders.count == 3)

        let gone = model(folder: "a-folder-that-is-not-there")
        await gone.loadFolders()
        #expect(gone.folder == nil)
    }

    @Test("closing drops the paste and the rows")
    func clearOnClose() async {
        let paste = model()
        paste.text = Paste.env
        await paste.detectNow()
        #expect(!paste.rows.isEmpty)
        paste.clear()
        #expect(paste.text.isEmpty)
        #expect(paste.rows.isEmpty)
        #expect(paste.maskedText.isEmpty)
        // A detection that was waiting does not bring the rows back.
        paste.text = Paste.stripe
        paste.clear()
        try? await Task.sleep(for: .milliseconds(120))
        #expect(paste.rows.isEmpty)
    }

    @Test("the folder menu lists the tree with depths, after No folder")
    func folderChoices() async throws {
        let folders = try await PreviewVaultService(unlocked: true).folders()
        let choices = FolderMenu.choices(folders)
        #expect(choices.map(\.name) == ["No folder", "Acme", "Billing", "Personal"])
        #expect(choices.map(\.depth) == [0, 0, 1, 0])
        #expect(choices.first?.id == nil)
        #expect(FolderMenu.label(folders, billing) == "Acme › Billing")
        #expect(FolderMenu.label(folders, nil) == "No folder")
    }
}

@MainActor
@Suite("ItemEditorModel folder")
struct ItemEditorFolderTests {
    private let acme = PreviewOrganize.FolderID.acme
    private let personal = PreviewOrganize.FolderID.personal

    @Test("a new item goes into the chosen folder after the save")
    func newItemFolder() async throws {
        let service = PreviewVaultService(unlocked: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let editor = ItemEditorModel(kind: .login, folder: personal)
        await editor.loadFolders(from: service)
        #expect(editor.folder == personal)
        #expect(editor.movesFolder)
        #expect(editor.folderLabel == "Personal")
        editor.title = "Example"
        editor.values["username"] = "u"
        editor.values["password"] = "p"
        let saved = try #require(await editor.save(in: vault))
        #expect(vault.item(saved.id)?.folder == personal)
        #expect(vault.alert == nil)
    }

    @Test("a new item without a folder stays at the top level")
    func newItemNoFolder() async throws {
        let service = PreviewVaultService(unlocked: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let editor = ItemEditorModel(kind: .login)
        await editor.loadFolders(from: service)
        #expect(!editor.movesFolder)
        editor.title = "Example"
        editor.values["username"] = "u"
        editor.values["password"] = "p"
        let saved = try #require(await editor.save(in: vault))
        #expect(vault.item(saved.id)?.folder == nil)
    }

    @Test("an edited item moves only when its folder changed")
    func existingItemFolder() async throws {
        let service = PreviewVaultService(unlocked: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let editor = ItemEditorModel(detail: try await service.item(id: 100))
        await editor.loadFolders(from: service)
        #expect(editor.folder == acme)
        #expect(editor.storedFolder == acme)
        #expect(!editor.movesFolder)
        editor.folder = personal
        #expect(editor.movesFolder)
        editor.folder = acme
        #expect(!editor.movesFolder)

        editor.folder = nil
        _ = try #require(await editor.save(in: vault))
        #expect(vault.item(100)?.folder == nil)
        #expect(editor.storedFolder == nil)
        #expect(!editor.movesFolder)
    }

    @Test("a folder that is gone reads as the top level and is no change")
    func goneFolder() async throws {
        let service = PreviewVaultService(unlocked: true)
        let editor = ItemEditorModel(detail: try await service.item(id: 100))
        _ = try await service.deleteFolder(uuid: acme)
        await editor.loadFolders(from: service)
        #expect(editor.folder == nil)
        #expect(!editor.movesFolder)
    }

    @Test("a failed move keeps the saved item and shows the alert of the vault")
    func failedMove() async throws {
        let service = PreviewVaultService(unlocked: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let editor = ItemEditorModel(kind: .login, folder: personal)
        await editor.loadFolders(from: service)
        _ = try await service.deleteFolder(uuid: personal)
        editor.title = "Example"
        editor.values["username"] = "u"
        editor.values["password"] = "p"
        let saved = try #require(await editor.save(in: vault))
        #expect(vault.item(saved.id) != nil)
        #expect(vault.alert != nil)
        #expect(editor.error == nil)
    }
}
