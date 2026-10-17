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

    @Test("Add right after a change detects the new text first, shows its rows, and adds on the next tap")
    func addDetectsFirst() async throws {
        let service = PreviewVaultService(unlocked: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let paste = NewCredentialModel(service: service, folder: nil, debounce: .seconds(30))
        paste.text = Paste.stripe
        #expect(await paste.add(in: vault) == nil)
        #expect(paste.rows.map(\.found.title) == ["Stripe test"])
        #expect(paste.error == NewCredentialModel.rowsChanged)
        let added = try #require(await paste.add(in: vault))
        #expect(added.map(\.title) == ["Stripe test"])
        #expect(vault.item(added[0].id)?.folder == nil)
    }

    @Test("a text changed before the detection adds nothing on Add, and the rows are refreshed")
    func addAfterChangedText() async throws {
        let service = PreviewVaultService(unlocked: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let before = vault.items.count
        let paste = NewCredentialModel(service: service, folder: nil, debounce: .seconds(30))
        paste.text = Paste.env
        await paste.detectNow()
        #expect(paste.rows.count == 3)
        // The owner leaves out the GitHub token, then changes the text: the GitHub line moves up,
        // so the rows on the screen no longer match the text. The detection has not run yet.
        paste.setKeep(false, row: 1)
        paste.text = """
            GITHUB_TOKEN=ghp_EXAMPLE000000000000000000000000000000
            STRIPE_SECRET_KEY=sk_test_EXAMPLE00000000000000000000
            DATABASE_URL=postgres://app:EXAMPLE-password@db.example.com:5432/app
            """
        #expect(!paste.isCurrent)
        #expect(paste.keptCount == 2)

        #expect(await paste.add(in: vault) == nil)
        #expect(vault.items.count == before)
        #expect(paste.error == NewCredentialModel.rowsChanged)
        #expect(paste.isCurrent)
        #expect(paste.rows.map(\.found.envName) == ["GITHUB_TOKEN", "STRIPE_SECRET_KEY", "DATABASE_URL"])
        #expect(paste.rows.map(\.found.line) == [1, 2, 3])
        #expect(!paste.text.isEmpty)
    }

    @Test("Add with the rows on the screen still matching the text adds the checked rows")
    func addAfterSameRows() async throws {
        let service = PreviewVaultService(unlocked: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let paste = NewCredentialModel(service: service, folder: nil, debounce: .seconds(30))
        paste.text = Paste.env
        await paste.detectNow()
        paste.setKeep(false, row: 1)
        // A trailing newline: the same rows, the same lines.
        paste.text = Paste.env + "\n"
        let added = try #require(await paste.add(in: vault))
        #expect(added.count == 2)
        #expect(!vault.activeItems.contains { $0.title.hasPrefix("GitHub token") })
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

    @Test("loading folder choices preserves an explicit destination even when it is gone")
    func folderDefault() async {
        let none = model()
        await none.loadFolders()
        #expect(none.folder == nil)
        #expect(none.folderLabel == "No folder")
        #expect(none.folders.count == 3)

        let gone = model(folder: "a-folder-that-is-not-there")
        await gone.loadFolders()
        #expect(gone.folder == "a-folder-that-is-not-there")
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

    @Test("the paste goes when revealed values go, and the sheet keeps its folder")
    func dropsWithRevealedValues() async {
        let (vault, _) = makeVault(service: PreviewVaultService(unlocked: true))
        await vault.start()
        defer { vault.stopSync() }
        let paste = model(folder: billing)
        paste.follow(revealEpoch: vault.revealEpoch)
        paste.text = Paste.env
        await paste.detectNow()
        #expect(paste.rows.count == 3)
        // Seeing the same epoch again changes nothing.
        paste.follow(revealEpoch: vault.revealEpoch)
        #expect(paste.text == Paste.env)

        vault.enterBackground()
        paste.follow(revealEpoch: vault.revealEpoch)
        #expect(paste.text.isEmpty)
        #expect(paste.rows.isEmpty)
        #expect(paste.maskedText.isEmpty)
        #expect(paste.folder == billing)
        await vault.settle()
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

    @Test("a failed move retains a saved identity and retries the same item without a duplicate")
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
        let before = vault.items.count
        #expect(await editor.save(in: vault) == nil)
        let saved = try #require(editor.savedItem)
        #expect(vault.item(saved.id) != nil)
        #expect(vault.item(saved.id)?.folder == nil)
        #expect(vault.items.count == before + 1)
        #expect(editor.error?.contains("Saved “Example”, but could not move it to Personal.") == true)
        #expect(editor.moveFailure == editor.error)
        #expect(editor.preventsDismissal)
        #expect(vault.alert == nil)

        // Retry changes destination; no second create and no duplicate content revision.
        editor.folder = acme
        let retried = try #require(await editor.save(in: vault))
        #expect(retried.id == saved.id)
        #expect(retried.revision == saved.revision)
        #expect(vault.items.count == before + 1)
        #expect(vault.item(saved.id)?.folder == acme)
        #expect(editor.error == nil)
        #expect(editor.moveFailure == nil)
    }
}

@MainActor
@Suite("Paste submission safety")
struct PasteSubmissionTests {
    @Test("a delayed Add freezes row choices and submits its original text and folder once")
    func stablePaste() async throws {
        let service = SpyVaultService(organize: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let billing = PreviewOrganize.FolderID.billing
        let paste = NewCredentialModel(service: service, folder: billing, debounce: .seconds(30))
        paste.text = Paste.env
        await paste.detectNow()
        paste.setTitle("Submitted Stripe", row: 0)
        paste.setKeep(false, row: 1)
        let gate = VaultCallGate()
        await service.setPasteHook { await gate.wait() }
        defer { gate.release() }
        let task = Task { await paste.add(in: vault) }
        #expect(await waitUntil { gate.isWaiting })
        #expect(paste.isAdding)
        #expect(paste.preventsDismissal)
        #expect(await paste.add(in: vault) == nil)
        paste.setTitle("Later title", row: 0)
        paste.setKeep(true, row: 1)
        #expect(paste.rows[0].title == "Submitted Stripe")
        #expect(!paste.rows[1].keep)
        paste.folder = PreviewOrganize.FolderID.personal
        gate.release()
        let added = try #require(await task.value)
        #expect(added.count == 2)
        #expect(added.first?.title == "Submitted Stripe")
        for item in added { #expect(vault.item(item.id)?.folder == billing) }
        #expect(paste.savedFolder == billing)
        #expect(await service.pasteCalls.count == 1)
        #expect(!paste.isAdding)
    }

    @Test("blank selected names are explained before persistence and preserve the paste")
    func blankName() async {
        let service = SpyVaultService(organize: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let paste = NewCredentialModel(service: service, folder: nil)
        paste.text = Paste.stripe
        await paste.detectNow()
        paste.setTitle("   ", row: 0)
        #expect(!paste.canAdd)
        #expect(paste.rows[0].nameValidationMessage == "Name is required.")
        #expect(await paste.add(in: vault) == nil)
        #expect(paste.error == "Name is required.")
        #expect(paste.text == Paste.stripe)
        #expect(paste.rows[0].title == "   ")
        #expect(await service.pasteCalls.isEmpty)
    }

    @Test("failed Add retains text, row choices and a missing destination until explicitly changed")
    func failedAddRetainsDestination() async throws {
        let service = PreviewVaultService(unlocked: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let personal = PreviewOrganize.FolderID.personal
        let paste = NewCredentialModel(service: service, folder: personal)
        await paste.loadFolders()
        paste.text = Paste.env
        await paste.detectNow()
        paste.setTitle("Kept Stripe", row: 0)
        paste.setKeep(false, row: 1)
        _ = try await service.deleteFolder(uuid: personal)
        let before = vault.items.count
        #expect(await paste.add(in: vault) == nil)
        #expect(paste.error?.contains("folder is gone") == true)
        #expect(paste.text == Paste.env)
        #expect(paste.rows[0].title == "Kept Stripe")
        #expect(!paste.rows[1].keep)
        #expect(paste.folder == personal)
        #expect(paste.preventsDismissal)
        #expect(vault.items.count == before)
        #expect(await paste.add(in: vault) == nil)
        paste.folder = nil
        let added = try #require(await paste.add(in: vault))
        #expect(added.count == 2)
    }

    @Test("background clearing during a suspended detection cannot submit stale pasted text")
    func clearedDuringDetection() async {
        let service = SpyVaultService(organize: true)
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let paste = NewCredentialModel(service: service, folder: nil, debounce: .seconds(30))
        paste.text = Paste.stripe
        let gate = VaultCallGate()
        await service.setDetectHook { await gate.wait() }
        defer { gate.release() }
        let task = Task { await paste.add(in: vault) }
        #expect(await waitUntil { gate.isWaiting })
        paste.clear()
        gate.release()
        #expect(await task.value == nil)
        #expect(await service.pasteCalls.isEmpty)
        #expect(paste.text.isEmpty)
        #expect(paste.rows.isEmpty)
        #expect(!paste.isAdding)
    }

    @Test("an older core without folder capability clears inherited destination and keeps the unavailable message")
    func noFolderCapability() async {
        let service = SpyVaultService.olderCore()
        let (vault, _) = makeVault(service: service)
        await vault.start()
        defer { vault.stopSync() }
        let paste = NewCredentialModel(service: service, folder: PreviewOrganize.FolderID.billing)
        await paste.loadFolders()
        #expect(paste.folder == nil)
        #expect(paste.folders.isEmpty)
        #expect(!paste.hasChanges)
        #expect(!paste.preventsDismissal)
        paste.text = Paste.stripe
        await paste.detectNow()
        #expect(paste.detectError == "This vault cannot add a pasted credential. Update Apassy.")
        #expect(await paste.add(in: vault) == nil)
        #expect(paste.error == paste.detectError)
        #expect(await service.pasteCalls.isEmpty)
    }
}
