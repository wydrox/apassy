import ApassyVaultKit
import SwiftUI

/// The root of the Vault tab, like the Mac sidebar (ADR 0026 §8): Watchtower as a card, "All
/// credentials", the folders, and the sync state. "+" opens New Credential.
struct VaultRootView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(VaultUI.self) private var ui

    var body: some View {
        @Bindable var ui = ui
        NavigationStack(path: $ui.homePath) {
            List {
                Section {
                    NavigationLink(value: VaultRoute.watchtower) {
                        if let report = vault.watchtower, report.issueCount > 0 {
                            WatchtowerCard(report: report)
                        } else {
                            WatchtowerClearRow(checked: vault.watchtower != nil)
                        }
                    }
                }
                Section {
                    NavigationLink(value: VaultRoute.allCredentials) {
                        PlaceRow(
                            title: "All credentials", symbol: "key.horizontal.fill", color: .accentColor,
                            count: vault.activeItems.count)
                    }
                    let archived = VaultQuery.archived(vault.items).count
                    if archived > 0 {
                        NavigationLink(value: VaultRoute.category(.archive)) {
                            PlaceRow(title: "Archive", symbol: "archivebox.fill", color: .gray, count: archived)
                        }
                    }
                }
                if vault.hasFolders { folders }
                // Shared vaults (ADR 0026 §6) come with V3: a "Shared" section shows here only
                // when the core reports shared vaults. There is no such call yet.
            }
            .navigationTitle("Vault")
            .navigationSubtitle(subtitle)
            .toolbar { VaultToolbar(ui: ui, showsLock: true, vault: vault) }
            .vaultDestinations()
            .refreshable { await vault.syncNow() }
            .safeAreaInset(edge: .top, spacing: 0) {
                if vault.vault?.syncs == true {
                    SyncCapsule()
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                }
            }
            .folderPrompts()
            // A folder that is gone (deleted here or on a Mac) leaves the stack with the screens
            // above it.
            .onChange(of: vault.folders) { _, folders in
                guard vault.hasFolders,
                    let gone = ui.homePath.firstIndex(where: { route in
                        if case .folder(let uuid) = route { !folders.contains { $0.uuid == uuid } } else { false }
                    })
                else { return }
                ui.homePath.removeSubrange(gone...)
            }
        }
    }

    /// "Personal · 8 items · unlocked", as in the mockup.
    private var subtitle: String {
        let count = vault.activeItems.count
        let items = count == 1 ? "1 item" : "\(count) items"
        return [vault.vault?.name, items, "unlocked"].compactMap { $0 }.joined(separator: " · ")
    }

    private var folders: some View {
        let tree = vault.folderTree
        return Section {
            ForEach(tree.children(of: nil)) { folder in
                FolderListRow(folder: folder, tree: tree)
            }
            Button {
                ui.folderPrompt = .create(parent: nil)
            } label: {
                Label("New Folder", systemImage: "folder.badge.plus")
            }
        } header: {
            Text("Folders")
        }
    }
}

/// A place of the Vault root: a symbol tile, the title, and a count.
private struct PlaceRow: View {
    let title: String
    let symbol: String
    let color: Color
    let count: Int

    var body: some View {
        HStack(spacing: 12) {
            SymbolTile(symbol: symbol, color: color)
            Text(title)
            Spacer(minLength: 4)
            Text(count, format: .number)
                .foregroundStyle(.secondary)
                .monospacedDigit()
        }
        .accessibilityElement(children: .combine)
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

/// Watchtower on the Vault root when nothing needs a look (or the check has not finished yet).
private struct WatchtowerClearRow: View {
    let checked: Bool

    var body: some View {
        HStack(spacing: 12) {
            WatchtowerTile(issues: false)
            VStack(alignment: .leading, spacing: 2) {
                Text("Watchtower")
                    .font(.headline)
                Text(checked ? "Nothing needs a look" : "Checking")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityHint("Opens Watchtower")
    }
}

/// "Watchtower: 2 weak passwords · 1 reused" on the Vault root.
struct WatchtowerCard: View {
    let report: WatchtowerReport

    var body: some View {
        HStack(spacing: 12) {
            WatchtowerTile(issues: true)
            VStack(alignment: .leading, spacing: 2) {
                Text("Watchtower")
                    .font(.headline)
                Text(summary)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityHint("Opens Watchtower")
    }

    private var summary: String {
        var parts: [String] = []
        if !report.weak.isEmpty {
            parts.append(report.weak.count == 1 ? "1 weak password" : "\(report.weak.count) weak passwords")
        }
        let reused = report.reused.flatMap(\.self).count
        if reused > 0 { parts.append("\(reused) reused") }
        if !report.old.isEmpty { parts.append("\(report.old.count) old") }
        if !report.conflicts.isEmpty {
            parts.append(report.conflicts.count == 1 ? "1 conflict copy" : "\(report.conflicts.count) conflict copies")
        }
        return parts.joined(separator: " · ")
    }
}

/// The shield of Watchtower: green when nothing needs a look, orange otherwise.
private struct WatchtowerTile: View {
    let issues: Bool
    @ScaledMetric(relativeTo: .body) private var size: CGFloat = 36

    var body: some View {
        let tint: Color = issues ? .orange : .green
        Image(systemName: issues ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
            .font(.system(size: size * 0.55, weight: .medium))
            .foregroundStyle(tint)
            .frame(width: size, height: size)
            .background(tint.opacity(0.15), in: .rect(cornerRadius: size * 0.26, style: .continuous))
            .accessibilityHidden(true)
    }
}
