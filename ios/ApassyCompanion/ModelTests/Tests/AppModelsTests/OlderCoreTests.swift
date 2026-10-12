import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// A core without the calls of contract section 5.11 (folders, the paste, the options): the Vault
/// root, the credential screen, and the paste sheet show less, and nothing fails. And the changes
/// of section 5.11 sync, as a save does.
@MainActor
@Suite("Older core and the sync of folder changes")
struct OlderCoreTests {
    private func started(_ service: SpyVaultService) async -> VaultModel {
        let (vault, _) = makeVault(service: service)
        await vault.start()
        return vault
    }

    // MARK: An older core

    @Test("the Vault root has no folders section, and the rest of it stays")
    func rootWithoutFolders() async {
        let vault = await started(.olderCore())
        defer { vault.stopSync() }
        #expect(vault.isUnlocked)
        #expect(!vault.hasFolders)
        #expect(vault.folders.isEmpty)
        #expect(vault.folderTree.choices().isEmpty)
        #expect(vault.activeItems.count == 8)
        #expect(vault.alert == nil)
        // "All credentials" has one group, without a folder.
        #expect(vault.folderTree.groups(vault.activeItems).map(\.title) == [FolderTree.noFolder])
        // Favorites and Archive do not need the core.
        vault.toggleFavorite(101)
        #expect(vault.favoriteItems.map(\.id) == [101])
        #expect(VaultQuery.archived(vault.items).count == 1)
    }

    @Test("the credential screen has no Options group and no folder, and loads")
    func credentialWithoutOptions() async throws {
        let vault = await started(.olderCore())
        defer { vault.stopSync() }
        let model = ItemDetailModel(id: 101, vault: vault)
        await model.load()
        let detail = try #require(model.detail)
        #expect(model.loadError == nil)
        #expect(!CredentialOptions.isAvailable(detail))
        #expect(model.folderLabel == FolderTree.noFolder)
        #expect(CredentialLooks.environmentCap(detail) == nil)
        // The tile still comes from the service and the title.
        #expect(ProviderTileStyle.of(detail.row) == ProviderTileStyle(mark: .letter("S"), rgb: 0x635BFF))
        // The options cannot change, and nothing asks the owner.
        await model.setAlwaysAsk(true)
        #expect(model.detail?.alwaysAsk == nil)
        #expect(!model.isSavingOptions)
        #expect(vault.alert == nil)
    }

    @Test("the paste sheet shows the core's message, has no folder menu, and adds nothing")
    func pasteWithoutDetection() async {
        let vault = await started(.olderCore())
        defer { vault.stopSync() }
        let before = vault.items.count
        let paste = NewCredentialModel(
            service: vault.service, folder: PreviewOrganize.FolderID.billing, debounce: .milliseconds(40))
        await paste.loadFolders()
        #expect(paste.folders.isEmpty)
        #expect(paste.folder == nil)
        paste.text = "sk_test_EXAMPLE00000000000000000000"
        await paste.detectNow()
        #expect(paste.rows.isEmpty)
        #expect(paste.detectError == "This vault cannot add a pasted credential. Update Apassy.")
        #expect(!paste.showsNothingFound)
        #expect(!paste.canAdd)
        #expect(await paste.add(in: vault) == nil)
        #expect(paste.error == "This vault cannot add a pasted credential. Update Apassy.")
        #expect(vault.items.count == before)
    }

    @Test("the editor has no folder menu and saves")
    func editorWithoutFolders() async throws {
        let service = SpyVaultService.olderCore()
        let vault = await started(service)
        defer { vault.stopSync() }
        let editor = ItemEditorModel(kind: .login)
        await editor.loadFolders(from: service)
        #expect(editor.folders.isEmpty)
        #expect(!editor.movesFolder)
        editor.title = "Example"
        editor.values["username"] = "u"
        editor.values["password"] = "p"
        let saved = try #require(await editor.save(in: vault))
        #expect(vault.item(saved.id) != nil)
        #expect(editor.moveFailure == nil)
        #expect(vault.alert == nil)
    }

    // MARK: Sync after a folder change

    /// A started vault on a spy with the 5.11 calls, after its first sync, with the sync loop off:
    /// a later sync comes from `scheduleSync`.
    private func quietVault() async -> (VaultModel, SpyVaultService) {
        let spy = SpyVaultService(organize: true)
        let vault = await started(spy)
        _ = await waitUntil { spy.syncCount >= 1 }
        vault.stopSync()
        return (vault, spy)
    }

    @Test("making, renaming, moving, and deleting a folder each sync soon after")
    func folderChangesSync() async throws {
        let (vault, spy) = await quietVault()
        #expect(vault.hasFolders)

        var before = spy.syncCount
        let made = try #require(await vault.createFolder(parent: nil, name: "Clients"))
        #expect(await waitUntil(seconds: 1) { spy.syncCount > before })

        before = spy.syncCount
        #expect(await vault.renameFolder(made, to: "Customers"))
        #expect(await waitUntil(seconds: 1) { spy.syncCount > before })

        before = spy.syncCount
        let renamed = try #require(vault.folders.first { $0.uuid == made.uuid })
        #expect(await vault.moveFolder(renamed, to: PreviewOrganize.FolderID.acme))
        #expect(await waitUntil(seconds: 1) { spy.syncCount > before })

        before = spy.syncCount
        #expect(await vault.moveItem(102, to: made.uuid))
        #expect(await waitUntil(seconds: 1) { spy.syncCount > before })

        before = spy.syncCount
        let moved = try #require(vault.folders.first { $0.uuid == made.uuid })
        #expect(await vault.deleteFolder(moved) == 1)
        #expect(await waitUntil(seconds: 1) { spy.syncCount > before })
        #expect(vault.alert == nil)
    }

    // MARK: A failed move in the folder picker

    @Test("a failed move goes to the sheet that asked, not to the alert of the tabs")
    func capturedMoveFailure() async {
        let (vault, _) = await quietVault()
        let message = await vault.capturingAlert {
            await vault.moveItem(102, to: "a-folder-that-is-not-there")
        }
        #expect(message != nil)
        #expect(vault.alert == nil)
        #expect(vault.item(102)?.folder == nil)

        // Outside of it, a failure shows as the alert again.
        await vault.moveItem(102, to: "a-folder-that-is-not-there")
        #expect(vault.alert == message)
    }

    @Test("two captures at once keep their own messages, and the alert works after them")
    func overlappingCaptures() async {
        let (vault, _) = await quietVault()
        async let a = vault.capturingAlert {
            await vault.moveItem(102, to: "missing-a")
        }
        async let b = vault.capturingAlert {
            await vault.moveItem(103, to: "missing-b")
        }
        let (messageA, messageB) = await (a, b)
        #expect(messageA != nil)
        #expect(messageB != nil)
        #expect(vault.alert == nil)

        // No capture is left behind: a failure outside of them shows as the alert.
        await vault.moveItem(102, to: "missing-c")
        #expect(vault.alert != nil)
    }

    @Test("a move that works reports nothing")
    func capturedMoveSuccess() async {
        let (vault, _) = await quietVault()
        let message = await vault.capturingAlert {
            await vault.moveItem(102, to: PreviewOrganize.FolderID.personal)
        }
        #expect(message == nil)
        #expect(vault.item(102)?.folder == PreviewOrganize.FolderID.personal)
    }

    // MARK: Favorites on the Vault root

    @Test("the favorites of the Vault root skip archived and deleted items, in the order added")
    func favoriteItems() async {
        let (vault, _) = await quietVault()
        #expect(vault.favoriteItems.isEmpty)
        vault.toggleFavorite(104)
        vault.toggleFavorite(100)
        vault.toggleFavorite(108)  // archived
        #expect(vault.favoriteItems.map(\.id) == [104, 100])
        vault.toggleFavorite(104)
        #expect(vault.favoriteItems.map(\.id) == [100])
    }
}
