import ApassyVaultKit
import SwiftUI

/// The unlocked vault: Vault, Decisions (the questions through the relay and the companion),
/// Agents, and Search (ADR 0026 §8). Watchtower and all items open from the Vault tab.
struct VaultTabView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(RootModel.self) private var root
    @State private var ui = VaultUI()

    var body: some View {
        @Bindable var ui = ui
        TabView(selection: $ui.tab) {
            Tab("Vault", systemImage: "key.horizontal", value: VaultTab.vault) {
                VaultRootView()
            }
            Tab("Decisions", systemImage: "checkmark.circle", value: VaultTab.decisions) {
                ApprovalsHub(
                    questions: root.questions, companion: root.companion, onSettings: { ui.sheet = .settings })
            }
            .badge(waitingCount)
            Tab("Agents", systemImage: "cpu", value: VaultTab.agents) {
                AgentsView()
            }
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
                case .syncSettings:
                    SettingsView(initialPage: .devices)
                case .new(let kind):
                    ItemEditorView(model: ItemEditorModel(kind: kind))
                case .edit(let detail):
                    ItemEditorView(model: ItemEditorModel(detail: detail))
                case .generator:
                    GeneratorView(model: GeneratorModel(service: vault.service), onUse: nil)
                case .exchange:
                    if let exchange = root.exchange {
                        NavigationStack { CredentialExchangeView(model: exchange, mode: .importing) }
                    }
                case .newCredential(let folder):
                    NewCredentialView(folder: folder)
                case .moveItem(let item):
                    FolderPicker(
                        title: "Move “\(item.title)”", selected: vault.folderTree.folder(of: item),
                        choices: vault.folderTree.choices()
                    ) { folder in
                        await vault.moveItem(item.id, to: folder)
                    }
                case .moveFolder(let folder):
                    FolderPicker(
                        title: "Move “\(folder.name)”", selected: folder.parent,
                        choices: vault.folderTree.moveTargets(for: folder.uuid), topLabel: "Top level"
                    ) { parent in
                        await vault.moveFolder(folder, to: parent)
                    }
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
        .questionsPolling(root.questions)
        // The owner opened the notification of a question.
        .onChange(of: root.questionsRequested, initial: true) { _, requested in
            guard requested else { return }
            ui.tab = .decisions
            root.questionsRequested = false
        }
        // Another app sent its logins: offer the import once the vault is open (it is, here).
        .onChange(of: root.exchange?.state, initial: true) { _, state in
            if state == .importWaiting, ui.sheet?.id != VaultSheet.exchange.id { ui.sheet = .exchange }
        }
        #if targetEnvironment(simulator)
            .task { openFromLaunchArgument() }
        #endif
    }

    /// The rows of Decisions, as it lists them: a run that a question shows counts once.
    private var waitingCount: Int {
        var session: SessionModel?
        if case .paired(let paired) = root.companion.phase { session = paired }
        return Decisions.badge(questions: root.questions?.questions ?? [], session: session, now: Date())
    }

    #if targetEnvironment(simulator)
        /// A development aid of the Simulator, to reach a screen without taps:
        /// `-ApassyOpen vault|items|all|watchtower|folder:<uuid or name>|decisions|approvals|questions|agents|settings[:<group>]|generator|search:<text>|new:<kind>|newcredential|edit:<id>|item:<id>[:reveal|:large|:options]`.
        /// `items` (`all`), `watchtower`, and `folder` open on the Vault tab, where they are now;
        /// `approvals` is the old name of `decisions`.
        private func openFromLaunchArgument() {
            guard let route = UserDefaults.standard.string(forKey: "ApassyOpen") else { return }
            let parts = route.split(separator: ":").map(String.init)
            switch parts.first {
            case "vault": ui.tab = .vault
            case "items", "all":
                ui.tab = .vault
                ui.homePath = [.allCredentials]
            case "watchtower":
                ui.tab = .vault
                ui.homePath = [.watchtower]
            case "folder":
                ui.tab = .vault
                let wanted = parts.dropFirst().joined(separator: ":")
                Task { await openFolder(wanted) }
            case "newcredential": ui.sheet = .newCredential(folder: nil)
            case "decisions", "approvals": ui.tab = .decisions
            case "questions": ui.tab = .decisions
            case "agents": ui.tab = .agents
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
                ui.demoOptions = parts.count > 2 && parts[2] == "options"
                ui.homePath = [.item(id)]
            case "edit":
                guard parts.count > 1, let id = UInt64(parts[1]) else { return }
                Task {
                    if let detail = try? await vault.service.item(id: id) { ui.sheet = .edit(detail) }
                }
            default: break
            }
        }

        /// Push the folders from the top level down to a folder, by its UUID or its name, once the
        /// folders are read.
        private func openFolder(_ wanted: String) async {
            for _ in 0..<50 where vault.folders.isEmpty {
                try? await Task.sleep(for: .milliseconds(100))
            }
            let tree = vault.folderTree
            guard
                let target = tree.folder(wanted)
                    ?? tree.folders.first(where: { $0.name.caseInsensitiveCompare(wanted) == .orderedSame })
            else { return }
            var chain: [VaultRoute] = []
            var at: Folder? = target
            while let folder = at, chain.count <= Folder.maxDepth {
                chain.insert(.folder(folder.uuid), at: 0)
                at = tree.folder(folder.parent)
            }
            ui.homePath = chain
        }
    #endif
}

// MARK: - Items

/// "All credentials": every credential that is not archived, grouped by folder as on the Mac
/// (ADR 0026 §1), with filters and a sort. The headers stay at the top while the list scrolls. The
/// Vault root pushes it.
struct ItemsView: View {
    @Environment(VaultModel.self) private var vault
    @State private var kind: ItemKind?
    @State private var tag: String?
    @State private var sort = ItemSort.title

    private var shown: [ItemRow] {
        VaultQuery.filter(vault.activeItems, kind: kind, tag: tag)
    }

    var body: some View {
        content
            .navigationTitle(kind?.pluralLabel ?? "All credentials")
            .navigationSubtitle(subtitle)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) { filterMenu }
                ToolbarSpacer(.fixed, placement: .topBarTrailing)
                ToolbarItem(placement: .topBarTrailing) { NewCredentialButton(folder: nil) }
            }
    }

    @ViewBuilder
    private var content: some View {
        let items = shown
        if vault.activeItems.isEmpty {
            ContentUnavailableView {
                Label("No credentials yet", systemImage: "key")
            } description: {
                Text("Paste a key, a .env file, or a password with the + button, or add it on your Mac.")
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
            // As on the Mac: no folder first, then each folder by its path, A–Z inside.
            List {
                ForEach(vault.folderTree.groups(items)) { group in
                    Section {
                        ForEach(group.items) { item in
                            ItemListRow(item: item)
                        }
                    } header: {
                        Text(group.title)
                    }
                }
            }
            .listStyle(.plain)
        } else {
            List(VaultQuery.sorted(items, by: .changed)) { item in
                ItemListRow(item: item)
            }
            .listStyle(.plain)
        }
    }

    private var subtitle: String {
        let count = shown.count
        return count == 1 ? "1 item" : "\(count) items"
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
