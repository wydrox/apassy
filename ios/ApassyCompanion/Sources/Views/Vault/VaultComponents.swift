import ApassyVaultKit
import SwiftUI

enum VaultTab: Hashable {
    case home
    case items
    case watchtower
    case approvals
    case search
}

/// A screen pushed in a tab.
enum VaultRoute: Hashable {
    case item(UInt64)
    case category(ItemCategory)
}

/// A sheet of the vault tabs.
enum VaultSheet: Identifiable {
    case settings
    case new(ItemKind)
    case edit(ItemDetail)
    case generator
    /// An import from another app (Apple's credential exchange).
    case exchange

    var id: String {
        switch self {
        case .settings: "settings"
        case .new(let kind): "new-\(kind.rawValue)"
        case .edit(let detail): "edit-\(detail.id)"
        case .generator: "generator"
        case .exchange: "exchange"
        }
    }
}

/// What the vault tabs show: the tab, the sheet, and the stack of each tab.
@MainActor
@Observable
final class VaultUI {
    var tab = VaultTab.home
    var sheet: VaultSheet?
    var homePath: [VaultRoute] = []
    var itemsPath: [VaultRoute] = []
    var searchText = ""
    #if targetEnvironment(simulator)
        /// A development aid: the item screen reveals its first secret once, or shows it in large
        /// type (after the owner check).
        var demoReveal = false
        var demoLargeType = false
    #endif
}

extension ItemKind {
    /// The color of the icon of the kind.
    var tint: Color {
        switch self {
        case .login: .blue
        case .apiKey: .orange
        case .sshKey: .indigo
        case .database: .green
        case .custom: .purple
        }
    }
}

/// The symbol of a kind in a rounded square.
struct ItemIcon: View {
    let kind: ItemKind
    @ScaledMetric(relativeTo: .body) private var size: CGFloat = 36
    var scale: CGFloat = 1

    var body: some View {
        let side = size * scale
        Image(systemName: kind.symbol)
            .font(.system(size: side * 0.46, weight: .medium))
            .foregroundStyle(.white)
            .frame(width: side, height: side)
            .background(kind.tint.gradient, in: .rect(cornerRadius: side * 0.26, style: .continuous))
            .accessibilityHidden(true)
    }
}

/// An item in a list: its icon, title, and subtitle, with marks for a code and a conflict copy.
struct ItemRowView: View {
    let item: ItemRow
    var favorite = false

    var body: some View {
        HStack(spacing: 12) {
            ItemIcon(kind: item.kind)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(item.title)
                        .font(.body)
                        .lineLimit(1)
                    if favorite {
                        Image(systemName: "star.fill")
                            .font(.caption2)
                            .foregroundStyle(.yellow)
                            .accessibilityLabel("Favorite")
                    }
                }
                if !detailText.isEmpty {
                    Text(detailText)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 4)
            if item.conflictOf != nil {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .accessibilityLabel("Conflict copy")
            }
            if item.hasTotp {
                Image(systemName: "clock.badge.checkmark")
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("Has a one-time password")
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var detailText: String {
        if !item.subtitle.isEmpty { return item.subtitle }
        if let site = item.websites.first { return VaultText.host(site) }
        return item.kind.label
    }
}

/// A row that opens the item, with the swipe actions and the context menu of the lists.
struct ItemListRow: View {
    let item: ItemRow
    @Environment(VaultModel.self) private var vault
    @Environment(\.openURL) private var openURL

    var body: some View {
        NavigationLink(value: VaultRoute.item(item.id)) {
            ItemRowView(item: item, favorite: vault.isFavorite(item.id))
        }
        .swipeActions(edge: .leading, allowsFullSwipe: true) {
            Button {
                Task { await vault.copyMainSecret(item) }
            } label: {
                Label("Copy \(VaultText.phrase(VaultModel.mainSecretLabel(item.kind)))", systemImage: "key.fill")
            }
            .tint(.blue)
            if !item.subtitle.isEmpty, item.kind == .login || item.kind == .database {
                Button {
                    vault.copyUsername(item)
                } label: {
                    Label("Copy username", systemImage: "person.fill")
                }
                .tint(.gray)
            }
        }
        .swipeActions(edge: .trailing) {
            Button {
                Task { await vault.setArchived(item, !item.archived) }
            } label: {
                Label(item.archived ? "Restore" : "Archive", systemImage: item.archived ? "tray.and.arrow.up" : "archivebox")
            }
            .tint(.orange)
            if !item.archived {
                Button {
                    vault.toggleFavorite(item.id)
                } label: {
                    Label(
                        vault.isFavorite(item.id) ? "Remove from favorites" : "Favorite",
                        systemImage: vault.isFavorite(item.id) ? "star.slash" : "star")
                }
                .tint(.yellow)
            }
        }
        .contextMenu {
            if !item.subtitle.isEmpty, item.kind == .login || item.kind == .database {
                Button("Copy username", systemImage: "person") { vault.copyUsername(item) }
            }
            Button("Copy \(VaultText.phrase(VaultModel.mainSecretLabel(item.kind)))", systemImage: "key") {
                Task { await vault.copyMainSecret(item) }
            }
            if let site = item.websites.first, let url = VaultText.websiteURL(site) {
                Button("Open \(VaultText.host(site))", systemImage: "safari") { openURL(url) }
            }
            Divider()
            if !item.archived {
                Button(
                    vault.isFavorite(item.id) ? "Remove from favorites" : "Favorite",
                    systemImage: vault.isFavorite(item.id) ? "star.slash" : "star"
                ) { vault.toggleFavorite(item.id) }
            }
            Button(item.archived ? "Restore" : "Archive", systemImage: item.archived ? "tray.and.arrow.up" : "archivebox") {
                Task { await vault.setArchived(item, !item.archived) }
            }
        }
    }
}

/// A secret as text: digits and symbols in their own colors, so `0` and `O`, `1` and `l` differ.
enum SecretText {
    static func attributed(_ value: String) -> AttributedString {
        var text = AttributedString()
        for character in value {
            var piece = AttributedString(String(character))
            switch VaultText.characterClass(character) {
            case .digit: piece.foregroundColor = .blue
            case .symbol: piece.foregroundColor = .orange
            case .letter, .space: break
            }
            text += piece
        }
        return text
    }
}

/// The dots of a hidden secret. VoiceOver reads "hidden".
struct HiddenSecret: View {
    var body: some View {
        Text(verbatim: "••••••••••")
            .font(.body.monospaced())
            .foregroundStyle(.secondary)
            .accessibilityLabel("hidden")
    }
}

/// The state of the relay sync as a floating glass capsule. Selecting it syncs now.
struct SyncCapsule: View {
    @Environment(VaultModel.self) private var vault

    var body: some View {
        Button {
            Task { await vault.syncNow() }
        } label: {
            HStack(spacing: 8) {
                if vault.isSyncing {
                    ProgressView()
                } else {
                    Image(systemName: symbol)
                        .foregroundStyle(tint ?? .primary)
                }
                Text(title)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .glassEffect(.regular.tint(tint?.opacity(0.28)).interactive(), in: .capsule)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .accessibilityHint("Syncs now")
    }

    private var title: String {
        if vault.isSyncing { return "Syncing" }
        guard let status = vault.syncStatus, !status.message.isEmpty else { return "Not synced yet" }
        return status.message
    }

    private var symbol: String {
        switch vault.syncStatus?.state {
        case .ok?: "checkmark.circle.fill"
        case .offline?: "wifi.exclamationmark"
        case .needsPassphrase?: "key.fill"
        case .removed?, .damaged?, .staleCopy?, .forkedCopy?, .error?: "exclamationmark.triangle.fill"
        default: "arrow.triangle.2.circlepath"
        }
    }

    private var tint: Color? {
        switch vault.syncStatus?.state {
        case .ok?: .green
        case .offline?, .busy?, .needsPassphrase?: .orange
        case .removed?, .damaged?, .staleCopy?, .forkedCopy?, .error?: .red
        default: nil
        }
    }
}

/// The "+" menu: a new item of a kind, or the password generator.
struct NewItemMenu: View {
    @Environment(VaultUI.self) private var ui

    var body: some View {
        Menu {
            Section("New item") {
                ForEach(ItemKind.allCases) { kind in
                    Button(kind.label, systemImage: kind.symbol) { ui.sheet = .new(kind) }
                }
            }
            Button("Password generator", systemImage: "dice") { ui.sheet = .generator }
        } label: {
            Label("New item", systemImage: "plus")
        }
    }
}

/// The toolbar of Home and Items: settings, and the "+" menu.
struct VaultToolbar: ToolbarContent {
    let ui: VaultUI
    var showsLock = false
    let vault: VaultModel

    var body: some ToolbarContent {
        ToolbarItem(placement: .topBarLeading) {
            Button {
                ui.sheet = .settings
            } label: {
                Label("Settings", systemImage: "gearshape")
            }
        }
        if showsLock {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    Task { await vault.lock() }
                } label: {
                    Label("Lock now", systemImage: "lock")
                }
            }
        }
        ToolbarItem(placement: .topBarTrailing) {
            NewItemMenu()
        }
    }
}

extension View {
    /// The screens that a vault tab pushes.
    func vaultDestinations() -> some View {
        navigationDestination(for: VaultRoute.self) { route in
            switch route {
            case .item(let id): ItemDetailScreen(id: id)
            case .category(let category): CategoryListView(category: category)
            }
        }
    }
}

/// The items of one category of Home.
struct CategoryListView: View {
    let category: ItemCategory
    @Environment(VaultModel.self) private var vault

    var body: some View {
        let items = VaultQuery.sorted(VaultQuery.items(vault.items, in: category), by: .title)
        Group {
            if items.isEmpty {
                ContentUnavailableView(
                    "No items in “\(category.label)”", systemImage: category.symbol,
                    description: Text(category == .archive ? "Archived items show here." : "Add one with the + button."))
            } else {
                List(items) { item in
                    ItemListRow(item: item)
                }
            }
        }
        .navigationTitle(category.label)
    }
}
