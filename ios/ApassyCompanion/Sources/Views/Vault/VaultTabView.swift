import ApassyVaultKit
import SwiftUI

/// Daily destinations: credentials, requests through the relay and companion, and Search.
/// Agent Access is available through Settings and credential context.
struct VaultTabView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(RootModel.self) private var root
    @State private var ui = VaultUI()
    /// Keep an incoming credential exchange queued until the current sheet finishes dismissal.
    @State private var presentedSheetID: String?

    var body: some View {
        @Bindable var ui = ui
        TabView(selection: $ui.tab) {
            Tab("Vault", systemImage: "key.horizontal", value: VaultTab.vault) {
                VaultRootView()
            }
            Tab("Requests", systemImage: "checkmark.circle", value: VaultTab.decisions) {
                ApprovalsHub(
                    questions: root.questions, companion: root.companion,
                    onSettings: { ui.sheet = .settings },
                    isPresented: ui.tab == .decisions && ui.sheet == nil && presentedSheetID == nil
                        && vault.alert == nil)
            }
            .badge(waitingCount)
            Tab(value: VaultTab.search, role: .search) {
                SearchView()
            }
        }
        .tabBarMinimizeBehavior(.onScrollDown)
        .environment(ui)
        .sheet(
            item: $ui.sheet,
            onDismiss: {
                // Swiping away the import is the same deferral as Not Now, not a new offer.
                if presentedSheetID == VaultSheet.exchange.id, root.exchange?.state == .importWaiting {
                    root.exchange?.cancelImport()
                }
                presentedSheetID = nil
                presentWaitingImport()
            }
        ) { sheet in
            Group {
                switch sheet {
                case .settings:
                    SettingsView()
                case .agentAccess:
                    SettingsView(initialPage: .agents)
                case .syncSettings:
                    SettingsView(initialPage: .devices)
                case .new(let kind):
                    ItemEditorView(model: ItemEditorModel(kind: kind), onSaved: showSaved)
                case .edit(let detail):
                    ItemEditorView(model: ItemEditorModel(detail: detail), onSaved: showSaved)
                case .generator:
                    GeneratorView(model: GeneratorModel(service: vault.service), onUse: nil)
                case .exchange:
                    if let exchange = root.exchange {
                        NavigationStack { CredentialExchangeView(model: exchange, mode: .importing) }
                    }
                case .newCredential(let folder):
                    NewCredentialView(folder: folder, onSaved: showSaved)
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
            .onAppear { presentedSheetID = sheet.id }
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
            // A Settings destination must not cover the refreshed request list.
            // Creation and edit sheets keep their drafts until the owner dismisses them.
            switch ui.sheet {
            case .settings?, .syncSettings?, .agentAccess?: ui.sheet = nil
            default: break
            }
            ui.tab = .decisions
            root.questionsRequested = false
        }
        // Retain the exchange token in its model while an editor or another sheet is open.
        // A dirty draft or an in-flight save must never be replaced by an incoming import.
        .onChange(of: root.exchange?.state, initial: true) { _, _ in
            presentWaitingImport()
        }
        #if targetEnvironment(simulator)
            .task { openFromLaunchArgument() }
        #endif
        // On the tabs, not on Decisions: Settings Agent Access shares the seeded state.
        #if DEBUG && targetEnvironment(simulator)
            .decisionsPreviewSeed(root.questions)
        #endif
    }

    private func presentWaitingImport() {
        guard root.exchange?.state == .importWaiting,
            ui.sheet == nil, presentedSheetID == nil
        else { return }
        ui.sheet = .exchange
    }

    private func showSaved(_ items: [(id: UInt64, title: String)], folder: String?) {
        guard !items.isEmpty else { return }
        ui.sheet = nil
        ui.tab = .vault
        ui.libraryRevealEpoch += 1
        if items.count == 1, let item = items.first {
            ui.homePath = [.item(item.id)]
        } else {
            ui.homePath = folder.map { [.folder($0)] } ?? []
        }
        let destination =
            folder.map { vault.folderTree.folder($0) == nil ? "the selected folder" : vault.folderTree.pathLabel($0) }
            ?? FolderTree.noFolder
        let description = items.count == 1 ? "“\(items[0].title)”" : "\(items.count) credentials"
        Toast.shared.show("\(description) saved in \(destination).")
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
            case "agents": ui.sheet = .agentAccess
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
/// Vault root renders this list directly; Folders also offers its unfiltered destination.
struct ItemsView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(RootModel.self) private var root
    var isRoot = false
    @Environment(VaultUI.self) private var ui
    @State private var kind: ItemKind?
    @State private var tag: String?
    @State private var sort = ItemSort.title

    private var shown: [ItemRow] {
        VaultQuery.filter(vault.activeItems, kind: kind, tag: tag)
    }

    var body: some View {
        navigationContent
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if isRoot {
                    ToolbarItem(placement: .principal) {
                        vaultSelector
                    }
                    ToolbarItem(placement: .topBarLeading) {
                        Button {
                            ui.sheet = .settings
                        } label: {
                            Label("Settings", systemImage: "gearshape")
                        }
                    }
                    ToolbarItem(placement: .topBarLeading) {
                        NavigationLink(value: VaultRoute.folders) {
                            Label("Folders and tools", systemImage: "folder")
                        }
                    }
                }
                ToolbarItem(placement: .topBarTrailing) { filterMenu }
                ToolbarSpacer(.fixed, placement: .topBarTrailing)
                ToolbarItem(placement: .topBarTrailing) { NewCredentialButton(folder: nil) }
            }
    }

    @ContentBuilder
    private var navigationContent: some View {
        if isRoot {
            content
                .navigationTitle(vault.vault?.name ?? "")
        } else {
            content
                .navigationTitle(kind?.pluralLabel ?? "All credentials")
                .navigationSubtitle(subtitle)
        }
    }

    private var vaultSelector: some View {
        Menu {
            ForEach(vault.vaults) { entry in
                Button {
                    // Use the same transition as Settings: lock before switching,
                    // then let the normal unlock screen authenticate the owner.
                    Task { await vault.select(vaultID: entry.id) }
                } label: {
                    if entry.id == vault.vault?.id {
                        Label(entry.name, systemImage: "checkmark")
                    } else {
                        Text(entry.name)
                    }
                }
                .disabled(entry.id == vault.vault?.id)
                .accessibilityIdentifier("vault.select.\(entry.id)")
            }
            Divider()
            Button("Add another vault", systemImage: "plus") {
                root.addVault()
            }
            .accessibilityIdentifier("vault.addAnother")
        } label: {
            HStack(spacing: 4) {
                Text(vault.vault?.name ?? "")
                    .font(.headline)
                    .lineLimit(1)
                    .truncationMode(.tail)
                Image(systemName: "chevron.down")
                    .font(.caption.weight(.semibold))
                    .accessibilityHidden(true)
            }
            // Fill the native inline title host without extending beyond its hit region.
            .frame(minWidth: 36, minHeight: 36)
            .contentShape(.rect)
        }
        .accessibilityLabel(vault.vault?.name ?? "")
        .accessibilityHint("Choose a vault")
        .accessibilityIdentifier("vault.selector")
    }

    private var content: some View {
        List {
            if isRoot {
                if showsSyncProblem {
                    Section { SyncCapsule() }
                }
            }
            if vault.activeItems.isEmpty {
                ContentUnavailableView {
                    Label("No credentials yet", systemImage: "key")
                } description: {
                    Text("Use New Credential to add a login, paste a key, or import from your Mac.")
                } actions: {
                    NewCredentialButton(folder: nil)
                }
            } else if shown.isEmpty {
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
                ForEach(vault.folderTree.groups(shown)) { group in
                    Section(group.title) {
                        ForEach(group.items) { item in ItemListRow(item: item) }
                    }
                }
            } else {
                ForEach(VaultQuery.sorted(shown, by: .changed)) { item in ItemListRow(item: item) }
            }
        }
        .listStyle(.plain)
    }

    private var showsSyncProblem: Bool {
        guard vault.vault?.syncs == true else { return false }
        return switch vault.syncStatus?.state {
        case .offline?, .needsPassphrase?, .removed?, .damaged?, .staleCopy?, .forkedCopy?, .error?:
            true
        default: false
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
            if isRoot {
                Divider()
                Button("Lock now", systemImage: "lock") { Task { await vault.lock() } }
            }
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
        @Bindable var ui = ui
        NavigationStack {
            results
                .navigationTitle("")
                .navigationBarTitleDisplayMode(.inline)
                .vaultDestinations()
        }
        // Here, not on the TabView: there the field reached the stack of every tab, and on Vault,
        // Decisions, and Agents it searched nothing.
        .searchable(text: $ui.searchText, prompt: "Titles, usernames, tags, websites")
    }

    @ViewBuilder
    private var results: some View {
        let found = VaultQuery.search(vault.items, text: ui.searchText)
        if ui.searchText.trimmingCharacters(in: .whitespaces).isEmpty {
            Color.clear
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
