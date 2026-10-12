import ApassyVaultKit
import SwiftUI

/// A folder (ADR 0026 §5, §8): its subfolders, then its credentials with provider tiles and a red
/// dot for production. "⋯" manages the folder; "+" adds a credential to it.
struct FolderView: View {
    let uuid: String
    @Environment(VaultModel.self) private var vault
    @Environment(VaultUI.self) private var ui

    var body: some View {
        let tree = vault.folderTree
        Group {
            if tree.folder(uuid) != nil {
                list(tree)
            } else {
                ContentUnavailableView(
                    "This folder is gone", systemImage: "folder",
                    description: Text("It was deleted on this iPhone or on a Mac. Its credentials moved to its parent."))
            }
        }
        .navigationTitle(tree.folder(uuid)?.name ?? "Folder")
        .navigationSubtitle(subtitle(tree))
        .toolbar {
            if let folder = tree.folder(uuid) {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        FolderMenuItems(folder: folder, tree: tree)
                    } label: {
                        Label("More", systemImage: "ellipsis")
                    }
                }
                ToolbarSpacer(.fixed, placement: .topBarTrailing)
                ToolbarItem(placement: .topBarTrailing) {
                    NewCredentialButton(folder: uuid)
                }
            }
        }
        .refreshable { await vault.syncNow() }
    }

    /// "Acme › Billing · 2 items": the path and the credentials in the folder and below it.
    private func subtitle(_ tree: FolderTree) -> String {
        guard tree.folder(uuid) != nil else { return "" }
        let count = tree.count(uuid, in: vault.items)
        return "\(tree.pathLabel(uuid)) · \(count == 1 ? "1 item" : "\(count) items")"
    }

    private func list(_ tree: FolderTree) -> some View {
        let children = tree.children(of: uuid)
        let items = tree.items(in: uuid, of: vault.items)
        return List {
            if !children.isEmpty {
                Section("Folders") {
                    ForEach(children) { folder in
                        FolderListRow(folder: folder, tree: tree)
                    }
                }
            }
            Section {
                if items.isEmpty {
                    Text("No credentials in this folder. Add one with the + button.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(items) { item in
                        ItemListRow(item: item)
                    }
                }
            } header: {
                if !children.isEmpty { Text("Credentials") }
            } footer: {
                Text("Agents see these names, never the values. The bouncer decides each use.")
            }
        }
    }
}

/// The actions on a folder, in its "⋯" menu and its context menu.
struct FolderMenuItems: View {
    let folder: Folder
    let tree: FolderTree
    @Environment(VaultUI.self) private var ui

    var body: some View {
        if tree.canHoldSubfolder(folder.uuid) {
            Button("New Folder", systemImage: "folder.badge.plus") { ui.folderPrompt = .create(parent: folder.uuid) }
        }
        Button("Rename", systemImage: "pencil") { ui.folderPrompt = .rename(folder) }
        Button("Move…", systemImage: "folder") { ui.sheet = .moveFolder(folder) }
        Divider()
        Button("Delete Folder", systemImage: "trash", role: .destructive) { ui.folderPrompt = .delete(folder) }
    }
}

/// New Folder, Rename, or Delete of a folder.
enum FolderPrompt: Identifiable, Equatable {
    /// A folder in `parent` (nil: the top level).
    case create(parent: String?)
    case rename(Folder)
    case delete(Folder)

    var id: String {
        switch self {
        case .create(let parent): "create-\(parent ?? "")"
        case .rename(let folder): "rename-\(folder.uuid)"
        case .delete(let folder): "delete-\(folder.uuid)"
        }
    }
}

extension View {
    /// The alerts of `VaultUI.folderPrompt`. The Vault tab has them once, around its stack.
    func folderPrompts() -> some View {
        modifier(FolderPrompts())
    }
}

/// The alerts of New Folder, Rename, and Delete. Deleting a folder moves its credentials and
/// subfolders to its parent; it never deletes a credential (ADR 0026 §5).
private struct FolderPrompts: ViewModifier {
    @Environment(VaultModel.self) private var vault
    @Environment(VaultUI.self) private var ui
    @State private var name = ""

    func body(content: Content) -> some View {
        content
            .alert(
                title, isPresented: Binding(get: { ui.folderPrompt != nil }, set: { if !$0 { ui.folderPrompt = nil } }),
                presenting: ui.folderPrompt
            ) { prompt in
                switch prompt {
                case .create(let parent):
                    TextField("Name", text: $name)
                    Button("Cancel", role: .cancel) {}
                    Button("Create") {
                        let typed = name
                        Task { await vault.createFolder(parent: parent, name: typed) }
                    }
                    .disabled(isBlank)
                case .rename(let folder):
                    TextField("Name", text: $name)
                    Button("Cancel", role: .cancel) {}
                    Button("Rename") {
                        let typed = name
                        Task { await vault.renameFolder(folder, to: typed) }
                    }
                    .disabled(isBlank)
                case .delete(let folder):
                    Button("Delete", role: .destructive) {
                        Task { await vault.deleteFolder(folder) }
                    }
                    Button("Cancel", role: .cancel) {}
                }
            } message: { prompt in
                Text(message(prompt))
            }
            .onChange(of: ui.folderPrompt?.id, initial: true) {
                if case .rename(let folder) = ui.folderPrompt { name = folder.name } else { name = "" }
            }
    }

    private var isBlank: Bool { name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    private var title: String {
        switch ui.folderPrompt {
        case .create?: "New Folder"
        case .rename?: "Rename Folder"
        case .delete(let folder)?: "Delete “\(folder.name)”?"
        case nil: ""
        }
    }

    private func message(_ prompt: FolderPrompt) -> String {
        let tree = vault.folderTree
        switch prompt {
        case .create(let parent):
            return parent == nil ? "A folder at the top level." : "A folder in “\(tree.pathLabel(parent))”."
        case .rename:
            return "Agents see the folder path as context."
        case .delete(let folder):
            let place = folder.parent.map { "“\(tree.pathLabel($0))”" } ?? "the top level"
            return "Its credentials and subfolders move to \(place). No credential is deleted."
        }
    }
}
