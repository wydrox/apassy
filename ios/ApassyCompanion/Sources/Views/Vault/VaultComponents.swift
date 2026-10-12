import ApassyVaultKit
import SwiftUI

/// The tabs of the unlocked vault (ADR 0026 §8).
enum VaultTab: Hashable {
    case vault
    case decisions
    case agents
    case search
}

/// A screen pushed in a tab.
enum VaultRoute: Hashable {
    case item(UInt64)
    case category(ItemCategory)
    /// A folder by its UUID.
    case folder(String)
    case allCredentials
    /// The favorites, from the Vault root.
    case favorites
    case watchtower
}

/// A sheet of the vault tabs.
enum VaultSheet: Identifiable {
    case settings
    case new(ItemKind)
    case edit(ItemDetail)
    case generator
    /// An import from another app (Apple's credential exchange).
    case exchange
    /// "New Credential" (ADR 0026 §4): paste, then Add, into the folder on the screen (nil at the
    /// root and in "All credentials").
    case newCredential(folder: String?)
    /// "Move to Folder" for a credential.
    case moveItem(ItemRow)
    /// "Move" for a folder.
    case moveFolder(Folder)

    var id: String {
        switch self {
        case .settings: "settings"
        case .new(let kind): "new-\(kind.rawValue)"
        case .edit(let detail): "edit-\(detail.id)"
        case .generator: "generator"
        case .exchange: "exchange"
        case .newCredential(let folder): "new-credential-\(folder ?? "")"
        case .moveItem(let item): "move-item-\(item.id)"
        case .moveFolder(let folder): "move-folder-\(folder.uuid)"
        }
    }
}

/// What the vault tabs show: the tab, the sheet, and the stack of each tab.
@MainActor
@Observable
final class VaultUI {
    var tab = VaultTab.vault
    var sheet: VaultSheet?
    /// New Folder, Rename, or Delete of a folder, as an alert over the Vault tab.
    var folderPrompt: FolderPrompt?
    var homePath: [VaultRoute] = []
    var itemsPath: [VaultRoute] = []
    var searchText = ""
    #if targetEnvironment(simulator)
        /// A development aid: the item screen reveals its first secret once, or shows it in large
        /// type (after the owner check).
        var demoReveal = false
        var demoLargeType = false
        /// The item screen scrolls to its options once.
        var demoOptions = false
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

/// A provider tile (Stripe, GitHub, Postgres…) as on the Mac, or the symbol of the kind when no
/// provider is known: a rounded square with a white letter or symbol.
struct ProviderTile: View {
    let style: ProviderTileStyle
    @ScaledMetric(relativeTo: .body) private var size: CGFloat = 38
    var scale: CGFloat = 1

    init(_ row: ItemRow, scale: CGFloat = 1) {
        self.init(style: ProviderTileStyle.of(row), scale: scale)
    }

    init(style: ProviderTileStyle, scale: CGFloat = 1) {
        self.style = style
        self.scale = scale
    }

    var body: some View {
        let side = size * scale
        Group {
            switch style.mark {
            case .letter(let letter):
                Text(verbatim: letter)
                    .font(.system(size: side * 0.45, weight: .bold))
            case .database:
                Image(systemName: "cylinder.split.1x2")
                    .font(.system(size: side * 0.46, weight: .medium))
            case .kind(let kind):
                Image(systemName: kind.symbol)
                    .font(.system(size: side * 0.46, weight: .medium))
            }
        }
        .foregroundStyle(.white)
        .frame(width: side, height: side)
        .background(color.gradient, in: .rect(cornerRadius: side * 0.26, style: .continuous))
        .accessibilityHidden(true)
    }

    private var color: Color {
        if let rgb = style.rgb { return Color(rgb: rgb) }
        if case .kind(let kind) = style.mark { return kind.tint }
        return .gray
    }
}

extension Color {
    /// A color from 0xRRGGBB.
    init(rgb: UInt32) {
        self.init(
            red: Double((rgb >> 16) & 0xFF) / 255, green: Double((rgb >> 8) & 0xFF) / 255,
            blue: Double(rgb & 0xFF) / 255)
    }

    /// The color of a folder tile.
    static let folderTile = Color(rgb: 0x5AC8FA)
}

/// A symbol in a small rounded square, as in System Settings: the rows of the Vault root.
struct SymbolTile: View {
    let symbol: String
    let color: Color
    @ScaledMetric(relativeTo: .body) private var size: CGFloat = 30

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.5, weight: .medium))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(color.gradient, in: .rect(cornerRadius: size * 0.27, style: .continuous))
            .accessibilityHidden(true)
    }
}

/// The red dot of a production credential.
struct ProductionDot: View {
    var body: some View {
        Circle()
            .fill(.red)
            .frame(width: 8, height: 8)
            .accessibilityElement()
            .accessibilityLabel("Production")
    }
}

/// A small tag of the credential header: "Production" in red, the others in gray.
struct CapView: View {
    let label: String
    var red = false
    var symbol: String?

    var body: some View {
        HStack(spacing: 4) {
            if let symbol {
                Image(systemName: symbol)
                    .font(.caption2.weight(.semibold))
                    .accessibilityHidden(true)
            }
            Text(label)
        }
        .font(.caption.weight(.semibold))
        .foregroundStyle(red ? Color.red : Color.secondary)
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(
            red ? AnyShapeStyle(Color.red.opacity(0.12)) : AnyShapeStyle(.fill.tertiary),
            in: .rect(cornerRadius: 7, style: .continuous))
    }
}

/// A credential in a list: its provider tile, title, one line of detail, a red dot for production,
/// and marks for a code and a conflict copy.
struct ItemRowView: View {
    let item: ItemRow
    var favorite = false

    var body: some View {
        HStack(spacing: 12) {
            ProviderTile(item)
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
                Text(CredentialLooks.detailLine(item))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
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
            if item.production == true {
                ProductionDot()
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// A row that opens the item, with the swipe actions and the context menu of the lists.
struct ItemListRow: View {
    let item: ItemRow
    @Environment(VaultModel.self) private var vault
    @Environment(VaultUI.self) private var ui
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
            if vault.hasFolders, !item.archived {
                Button("Move to Folder…", systemImage: "folder") { ui.sheet = .moveItem(item) }
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

/// "+": New Credential, into the folder on the screen (ADR 0026 §4).
struct NewCredentialButton: View {
    @Environment(VaultUI.self) private var ui
    var folder: String?

    var body: some View {
        Button {
            ui.sheet = .newCredential(folder: folder)
        } label: {
            Label("New Credential", systemImage: "plus")
        }
        .buttonStyle(.glassProminent)
    }
}

/// The toolbar of the Vault root: settings, the lock, and "+".
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
            ToolbarSpacer(.fixed, placement: .topBarTrailing)
        }
        ToolbarItem(placement: .topBarTrailing) {
            NewCredentialButton(folder: nil)
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
            case .folder(let uuid): FolderView(uuid: uuid)
            case .allCredentials: ItemsView()
            case .favorites: FavoritesView()
            case .watchtower: WatchtowerView()
            }
        }
    }
}

/// The items of one category: the archive, from the Vault root.
struct CategoryListView: View {
    let category: ItemCategory
    @Environment(VaultModel.self) private var vault

    var body: some View {
        let items = VaultQuery.sorted(VaultQuery.items(vault.items, in: category), by: .title)
        Group {
            if items.isEmpty {
                ContentUnavailableView(
                    "No items in “\(category.label)”", systemImage: category.symbol,
                    description: Text(category == .archive ? "Archived credentials show here." : "Add one with the + button."))
            } else {
                List(items) { item in
                    ItemListRow(item: item)
                }
            }
        }
        .navigationTitle(category.label)
    }
}
