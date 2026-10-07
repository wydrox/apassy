import ApassyVaultKit
import SwiftUI

/// The unlocked vault: Home, Items, Watchtower, Approvals, and Search.
struct VaultTabView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(RootModel.self) private var root
    @State private var ui = VaultUI()

    var body: some View {
        @Bindable var ui = ui
        TabView(selection: $ui.tab) {
            Tab("Home", systemImage: "house", value: VaultTab.home) {
                HomeView()
            }
            Tab("Items", systemImage: "list.bullet", value: VaultTab.items) {
                ItemsView()
            }
            Tab("Watchtower", systemImage: "checkmark.shield", value: VaultTab.watchtower) {
                WatchtowerView()
            }
            .badge(vault.watchtower?.issueCount ?? 0)
            Tab("Approvals", systemImage: "checkmark.seal", value: VaultTab.approvals) {
                ApprovalsView(app: root.companion, onSettings: { ui.sheet = .settings })
            }
            .badge(waitingCount)
            Tab(value: VaultTab.search, role: .search) {
                SearchView()
            }
        }
        .tabBarMinimizeBehavior(.onScrollDown)
        // On the TabView, the field belongs to the search tab and shows in the tab bar.
        .searchable(text: $ui.searchText, prompt: "Titles, usernames, tags, websites")
        .environment(ui)
        .sheet(item: $ui.sheet) { sheet in
            Group {
                switch sheet {
                case .settings:
                    SettingsView()
                case .new(let kind):
                    ItemEditorView(model: ItemEditorModel(kind: kind))
                case .edit(let detail):
                    ItemEditorView(model: ItemEditorModel(detail: detail))
                case .generator:
                    GeneratorView(model: GeneratorModel(service: vault.service), onUse: nil)
                }
            }
            .environment(vault)
            .environment(ui)
            .environment(root)
        }
        .alert(
            "Apassy could not finish",
            isPresented: Binding(get: { vault.alert != nil }, set: { if !$0 { vault.alert = nil } })
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(vault.alert ?? "")
        }
        .companionPolling(root.companion)
        #if targetEnvironment(simulator)
            .task { openFromLaunchArgument() }
        #endif
    }

    private var waitingCount: Int {
        if case .paired(let session) = root.companion.phase { return session.waitingCount }
        return 0
    }

    #if targetEnvironment(simulator)
        /// A development aid of the Simulator, to reach a screen without taps:
        /// `-ApassyOpen items|watchtower|approvals|settings|generator|search:<text>|new:<kind>|edit:<id>|item:<id>[:reveal|:large]`.
        private func openFromLaunchArgument() {
            guard let route = UserDefaults.standard.string(forKey: "ApassyOpen") else { return }
            let parts = route.split(separator: ":").map(String.init)
            switch parts.first {
            case "items": ui.tab = .items
            case "watchtower": ui.tab = .watchtower
            case "approvals": ui.tab = .approvals
            case "settings": ui.sheet = .settings
            case "generator": ui.sheet = .generator
            case "search":
                ui.tab = .search
                ui.searchText = parts.dropFirst().joined(separator: ":")
            case "new":
                ui.sheet = .new(ItemKind(rawValue: parts.count > 1 ? parts[1] : "login") ?? .login)
            case "item":
                guard parts.count > 1, let id = UInt64(parts[1]) else { return }
                ui.demoReveal = parts.count > 2 && parts[2] == "reveal"
                ui.demoLargeType = parts.count > 2 && parts[2] == "large"
                ui.homePath = [.item(id)]
            case "edit":
                guard parts.count > 1, let id = UInt64(parts[1]) else { return }
                Task {
                    if let detail = try? await vault.service.item(id: id) { ui.sheet = .edit(detail) }
                }
            default: break
            }
        }
    #endif
}

// MARK: - Home

/// Favorites, the recently changed items, the categories, Watchtower, and the sync state.
struct HomeView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(VaultUI.self) private var ui

    var body: some View {
        @Bindable var ui = ui
        NavigationStack(path: $ui.homePath) {
            List {
                if let report = vault.watchtower, report.issueCount > 0 {
                    Section {
                        Button {
                            ui.tab = .watchtower
                        } label: {
                            WatchtowerCard(report: report)
                        }
                        .buttonStyle(.plain)
                    }
                }
                favorites
                recent
                Section("Categories") {
                    ForEach(ItemCategory.all) { category in
                        NavigationLink(value: VaultRoute.category(category)) {
                            HStack {
                                Label(category.label, systemImage: category.symbol)
                                Spacer()
                                Text(VaultQuery.items(vault.items, in: category).count, format: .number)
                                    .foregroundStyle(.secondary)
                                    .monospacedDigit()
                            }
                        }
                    }
                }
            }
            .navigationTitle(vault.vault?.name ?? "Apassy")
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
        }
    }

    @ViewBuilder
    private var favorites: some View {
        let items = VaultQuery.favorites(vault.items, ids: vault.favoriteIDs)
        Section {
            if items.isEmpty {
                Text("Swipe an item to the left and select Favorite. It shows here.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(items) { item in
                    ItemListRow(item: item)
                }
            }
        } header: {
            Text("Favorites")
        }
    }

    @ViewBuilder
    private var recent: some View {
        let items = VaultQuery.recent(vault.items)
        if !items.isEmpty {
            Section("Recently changed") {
                ForEach(items) { item in
                    ItemListRow(item: item)
                }
            }
        }
    }
}

/// "3 items need a look" on Home.
struct WatchtowerCard: View {
    let report: WatchtowerReport

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: "exclamationmark.shield.fill")
                .font(.title)
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(report.issueCount == 1 ? "1 item needs a look" : "\(report.issueCount) items need a look")
                    .font(.headline)
                Text(summary)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            Image(systemName: "chevron.forward")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.tertiary)
                .accessibilityHidden(true)
        }
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
        .accessibilityHint("Opens Watchtower")
    }

    private var summary: String {
        var parts: [String] = []
        if !report.weak.isEmpty { parts.append("\(report.weak.count) weak") }
        let reused = report.reused.flatMap(\.self).count
        if reused > 0 { parts.append("\(reused) reused") }
        if !report.old.isEmpty { parts.append("\(report.old.count) old") }
        if !report.conflicts.isEmpty {
            parts.append(report.conflicts.count == 1 ? "1 conflict copy" : "\(report.conflicts.count) conflict copies")
        }
        return parts.joined(separator: ", ")
    }
}

// MARK: - Items

/// Every item that is not archived, A–Z with an index, with filters and a sort.
struct ItemsView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(VaultUI.self) private var ui
    @State private var kind: ItemKind?
    @State private var tag: String?
    @State private var sort = ItemSort.title

    private var shown: [ItemRow] {
        VaultQuery.filter(vault.activeItems, kind: kind, tag: tag)
    }

    var body: some View {
        @Bindable var ui = ui
        NavigationStack(path: $ui.itemsPath) {
            content
                .navigationTitle(kind?.pluralLabel ?? "Items")
                .toolbar {
                    VaultToolbar(ui: ui, vault: vault)
                    ToolbarItem(placement: .topBarTrailing) { filterMenu }
                }
                .vaultDestinations()
        }
    }

    @ViewBuilder
    private var content: some View {
        let items = shown
        if vault.activeItems.isEmpty {
            ContentUnavailableView {
                Label("No items yet", systemImage: "key")
            } description: {
                Text("Add a login, an API key, or another secret with the + button, or on your Mac.")
            }
        } else if items.isEmpty {
            ContentUnavailableView {
                Label("No items match", systemImage: "line.3.horizontal.decrease.circle")
            } description: {
                Text("No item has this category and this tag.")
            } actions: {
                Button("Show all items") {
                    kind = nil
                    tag = nil
                }
                .buttonStyle(.bordered)
            }
        } else if sort == .title {
            List {
                ForEach(VaultQuery.sections(items)) { section in
                    Section(section.letter) {
                        ForEach(section.items) { item in
                            ItemListRow(item: item)
                        }
                    }
                    .sectionIndexLabel(section.letter)
                }
            }
            .listSectionIndexVisibility(.visible)
        } else {
            List(VaultQuery.sorted(items, by: .changed)) { item in
                ItemListRow(item: item)
            }
        }
    }

    private var filterMenu: some View {
        Menu {
            Picker("Category", selection: $kind) {
                Text("All categories").tag(ItemKind?.none)
                ForEach(ItemKind.allCases) { kind in
                    Label(kind.pluralLabel, systemImage: kind.symbol).tag(ItemKind?.some(kind))
                }
            }
            let tags = VaultQuery.tags(vault.items)
            if !tags.isEmpty {
                Picker("Tag", selection: $tag) {
                    Text("All tags").tag(String?.none)
                    ForEach(tags, id: \.self) { tag in
                        Label(tag, systemImage: "tag").tag(String?.some(tag))
                    }
                }
                .pickerStyle(.menu)
            }
            Picker("Sort by", selection: $sort) {
                ForEach(ItemSort.allCases) { sort in
                    Text(sort.label).tag(sort)
                }
            }
            .pickerStyle(.menu)
        } label: {
            Label(
                "Filter and sort",
                systemImage: kind == nil && tag == nil
                    ? "line.3.horizontal.decrease.circle" : "line.3.horizontal.decrease.circle.fill")
        }
    }
}

// MARK: - Search

/// Search by title, username, tag, and website. Archived items in their own section.
struct SearchView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(VaultUI.self) private var ui

    var body: some View {
        NavigationStack {
            results
                .navigationTitle("Search")
                .vaultDestinations()
        }
    }

    @ViewBuilder
    private var results: some View {
        let found = VaultQuery.search(vault.items, text: ui.searchText)
        if ui.searchText.trimmingCharacters(in: .whitespaces).isEmpty {
            ContentUnavailableView(
                "Search the vault", systemImage: "magnifyingglass",
                description: Text("Find an item by its title, username, tag, or website."))
        } else if found.active.isEmpty, found.archived.isEmpty {
            ContentUnavailableView.search(text: ui.searchText)
        } else {
            List {
                if !found.active.isEmpty {
                    Section("Items") {
                        ForEach(found.active) { item in
                            ItemListRow(item: item)
                        }
                    }
                }
                if !found.archived.isEmpty {
                    Section("Archive") {
                        ForEach(found.archived) { item in
                            ItemListRow(item: item)
                        }
                    }
                }
            }
        }
    }
}
