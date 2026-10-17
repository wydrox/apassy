import ApassyVaultKit
import SwiftUI

/// Credentials are immediately available; organization and healthy status are secondary.
struct VaultRootView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(VaultUI.self) private var ui

    var body: some View {
        @Bindable var ui = ui
        NavigationStack(path: $ui.homePath) {
            ItemsView(isRoot: true)
                .id(ui.libraryRevealEpoch)
                .vaultDestinations()
                .refreshable { await vault.syncNow() }
                .folderPrompts()
                .onChange(of: vault.folders) { _, folders in
                    guard vault.hasFolders,
                        let gone = ui.homePath.firstIndex(where: { route in
                            if case .folder(let uuid) = route {
                                !folders.contains { $0.uuid == uuid }
                            } else {
                                false
                            }
                        })
                    else { return }
                    ui.homePath.removeSubrange(gone...)
                }
        }
    }
}

/// Organization and tools remain one tap from the credential list.
struct VaultFoldersView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(VaultUI.self) private var ui

    var body: some View {
        List {
            Section {
                NavigationLink(value: VaultRoute.allCredentials) {
                    PlaceRow(
                        title: "All credentials", symbol: "key.horizontal.fill", color: .accentColor,
                        count: vault.activeItems.count)
                }
                NavigationLink(value: VaultRoute.favorites) {
                    PlaceRow(
                        title: "Favorites", symbol: "star.fill", color: .yellow,
                        count: vault.favoriteItems.count)
                }
                NavigationLink(value: VaultRoute.category(.archive)) {
                    PlaceRow(
                        title: "Archive", symbol: "archivebox.fill", color: .gray,
                        count: VaultQuery.archived(vault.items).count)
                }
                NavigationLink(value: VaultRoute.watchtower) {
                    Label("Watchtower", systemImage: "checkmark.shield")
                }
                Button {
                    ui.sheet = .generator
                } label: {
                    Label("Password generator", systemImage: "dice")
                }
            }
            if vault.hasFolders {
                Section("Folders") {
                    let tree = vault.folderTree
                    ForEach(tree.children(of: nil)) { folder in
                        FolderListRow(folder: folder, tree: tree)
                    }
                    Button {
                        ui.folderPrompt = .create(parent: nil)
                    } label: {
                        Label("New Folder", systemImage: "folder.badge.plus")
                    }
                }
            }
        }
        .navigationTitle("Folders and tools")
    }
}

/// A place of the Vault root: a symbol tile, the title, and a count (none for a tool).
private struct PlaceRow: View {
    let title: String
    let symbol: String
    let color: Color
    var count: Int?

    var body: some View {
        HStack(spacing: 12) {
            SymbolTile(symbol: symbol, color: color)
            Text(title)
            Spacer(minLength: 4)
            if let count {
                Text(count, format: .number)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// The favorite credentials, in the order the owner added them, from the Vault root. A swipe or
/// the context menu removes one.
struct FavoritesView: View {
    @Environment(VaultModel.self) private var vault

    var body: some View {
        let items = vault.favoriteItems
        Group {
            if items.isEmpty {
                ContentUnavailableView(
                    "No favorites", systemImage: "star",
                    description: Text("Swipe a credential to the left and select Favorite. It shows here."))
            } else {
                List(items) { item in
                    ItemListRow(item: item)
                }
            }
        }
        .navigationTitle("Favorites")
    }
}

/// A folder in a list: its tile, its name, the names of its subfolders, and the count of the
/// credentials in it and below it. It opens the folder; a swipe or a long press manages it.
struct FolderListRow: View {
    let folder: Folder
    let tree: FolderTree
    @Environment(VaultModel.self) private var vault
    @Environment(VaultUI.self) private var ui

    var body: some View {
        NavigationLink(value: VaultRoute.folder(folder.uuid)) {
            HStack(spacing: 12) {
                SymbolTile(symbol: "folder.fill", color: .folderTile)
                VStack(alignment: .leading, spacing: 2) {
                    Text(folder.name)
                        .lineLimit(1)
                    let below = tree.childNames(folder.uuid)
                    if !below.isEmpty {
                        Text(below)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                Spacer(minLength: 4)
                Text(tree.count(folder.uuid, in: vault.items), format: .number)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
            .accessibilityElement(children: .combine)
        }
        .swipeActions(edge: .trailing) {
            Button {
                ui.folderPrompt = .delete(folder)
            } label: {
                Label("Delete", systemImage: "trash")
            }
            .tint(.red)
            Button {
                ui.folderPrompt = .rename(folder)
            } label: {
                Label("Rename", systemImage: "pencil")
            }
            .tint(.gray)
        }
        .contextMenu { FolderMenuItems(folder: folder, tree: tree) }
    }
}
