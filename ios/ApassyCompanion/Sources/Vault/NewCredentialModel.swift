import ApassyVaultKit
import Foundation
import Observation

/// "New Credential" (ADR 0025 §4, ADR 0026 §4 and §8): paste, then Add.
///
/// The owner pastes a key, a `KEY=value` line, a `.env` file, a database URL, or an `otpauth://`
/// link (or scans it as a QR code). The core detects each credential on this iPhone (contract
/// ios-core-v1, 5.11 `detect`) a moment after the text stops changing, and the sheet shows one row
/// for each. A paste with several credentials has a checkbox on each row. "Add" sends the text
/// again with the checked rows and the typed titles (`add_pasted`): the app never sends a detected
/// value back, and it never has one: a row holds the core's masked previews only.
///
/// The paste is a secret. It is never logged, and `clear()` drops it when the sheet closes. A Swift
/// `String` cannot be erased; this is best effort, as for a revealed value.
@MainActor
@Observable
final class NewCredentialModel {
    /// One detected credential and what the owner chose for it. It has no secret value.
    struct Row: Identifiable, Equatable {
        let found: DetectedCredential
        /// The title of the field; the detected title at first.
        var title: String
        /// Added on "Add"; every row at first.
        var keep: Bool

        var id: Int { found.index }

        /// The identity of a row across detections, as the Mac's `row_key`: its line, its variable,
        /// and its detected title. A row that stays keeps its title and its checkbox.
        var key: String { "\(found.line ?? 0)|\(found.envName ?? "")|\(found.title)" }

        /// The masks of the secret fields, such as `sk_live_••••••••`, from the core.
        var masked: String {
            let secrets = found.fields.filter(\.secret).map(\.preview)
            return secrets.isEmpty ? "••••••••" : secrets.joined(separator: " ")
        }

        /// The line of the masked paste: `STRIPE_SECRET_KEY=sk_live_••••••••` for a `.env` entry,
        /// the mask for a single value.
        var maskedLine: String {
            guard found.line != nil else { return masked }
            return "\(found.envName ?? found.title)=\(masked)"
        }
    }

    /// The note when "Add" found other rows than those on the screen: the text changed.
    static let rowsChanged = "The text changed. Check the credentials, then tap Add again."

    /// A row as `add` compares it: its index in the detection and its identity.
    private struct RowIdentity: Equatable {
        let index: Int
        let key: String
    }

    /// The note when a paste has no credential, as on the Mac.
    static let nothingFound =
        "Apassy found no credential in the text. Paste a secret, a KEY=value line, a .env file, a URL with a password, or an otpauth:// link."

    let service: any VaultService

    /// The paste. Each change starts a new detection after `debounce`.
    var text = "" {
        didSet { if text != oldValue { textChanged() } }
    }

    /// The rows of the last detection of `text`.
    private(set) var rows: [Row] = []
    private(set) var isDetecting = false
    /// Why the core could not detect: a text over 1 MB, or a core without detection.
    private(set) var detectError: String?
    /// The folder of the new credentials; nil: the top level.
    var folder: String?
    /// The folders of the vault, depth first. Empty with a core without folders.
    private(set) var folders: [Folder] = []
    private(set) var isAdding = false
    /// The message of a failed "Add".
    private(set) var error: String?

    @ObservationIgnored private let debounce: Duration
    @ObservationIgnored private var detectTask: Task<Void, Never>?
    /// Bumped by each change of `text`; an older detection does not apply.
    @ObservationIgnored private var generation = 0
    /// The generation that `rows` belong to.
    @ObservationIgnored private var detected = 0
    /// The last `revealEpoch` of the vault that `follow(revealEpoch:)` saw.
    @ObservationIgnored private var seenEpoch: Int?

    /// `folder`: the folder the sheet opened in (ADR 0026 §4).
    init(service: any VaultService, folder: String?, debounce: Duration = .milliseconds(300)) {
        self.service = service
        self.folder = folder
        self.debounce = debounce
    }

    // MARK: State for the sheet

    var hasText: Bool { !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    /// The rows are those of the text as it is now.
    var isCurrent: Bool { detected == generation }

    /// Several rows: each has a checkbox.
    var hasChoices: Bool { rows.count > 1 }

    var keptCount: Int { rows.filter(\.keep).count }

    var canAdd: Bool { !isAdding && hasText && keptCount > 0 }

    /// "Add", or "Add 3" for several rows.
    var addLabel: String { keptCount > 1 ? "Add \(keptCount)" : "Add" }

    /// A text with no credential: the calm hint, not an error.
    var showsNothingFound: Bool { hasText && isCurrent && !isDetecting && rows.isEmpty && detectError == nil }

    /// The paste as the field shows it while it is not edited: one masked line for each row.
    var maskedText: String {
        guard hasText else { return "" }
        guard isCurrent, !rows.isEmpty else { return "••••••••" }
        return rows.map(\.maskedLine).joined(separator: "\n")
    }

    /// "Acme › Billing", or "No folder".
    var folderLabel: String { FolderMenu.label(folders, folder) }

    // MARK: Detection

    private func textChanged() {
        detectTask?.cancel()
        generation += 1
        error = nil
        guard hasText else {
            rows = []
            detectError = nil
            isDetecting = false
            detected = generation
            return
        }
        let generation = generation
        let delay = debounce
        detectTask = Task { [weak self] in
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            await self?.detect(generation: generation)
        }
    }

    /// Detect the text now, without the wait: after the Paste button, a scan, and before "Add".
    func detectNow() async {
        detectTask?.cancel()
        guard !isCurrent else { return }
        await detect(generation: generation)
    }

    private func detect(generation: Int) async {
        let text = text
        isDetecting = true
        defer { if generation == self.generation { isDetecting = false } }
        do {
            let found = try await service.detect(text: text)
            guard generation == self.generation else { return }
            follow(found)
            detectError = nil
        } catch {
            guard generation == self.generation else { return }
            rows = []
            detectError = error.localizedDescription
        }
        detected = generation
    }

    /// Follow a new detection: a row that was there keeps its title and its checkbox.
    private func follow(_ found: [DetectedCredential]) {
        let old = rows
        rows = found.map { credential in
            let row = Row(found: credential, title: credential.title, keep: true)
            guard let before = old.first(where: { $0.key == row.key }) else { return row }
            return Row(found: credential, title: before.title, keep: before.keep)
        }
    }

    // MARK: Choices

    func setKeep(_ keep: Bool, row id: Int) {
        guard let index = rows.firstIndex(where: { $0.id == id }) else { return }
        rows[index].keep = keep
    }

    func setTitle(_ title: String, row id: Int) {
        guard let index = rows.firstIndex(where: { $0.id == id }) else { return }
        rows[index].title = title
    }

    /// The indexes of the checked rows.
    var pick: [Int] { rows.filter(\.keep).map(\.id) }

    /// The typed titles of the checked rows that differ from the detected title.
    var titles: [Int: String] {
        var titles: [Int: String] = [:]
        for row in rows where row.keep {
            let typed = row.title.trimmingCharacters(in: .whitespacesAndNewlines)
            if !typed.isEmpty, typed != row.found.title { titles[row.id] = typed }
        }
        return titles
    }

    // MARK: Folders

    /// Read the folders. A folder that another device deleted gives way to the top level.
    func loadFolders() async {
        folders = (try? await service.folders()) ?? []
        if let folder, !folders.contains(where: { $0.uuid == folder }) { self.folder = nil }
    }

    // MARK: Add

    /// Add the checked rows to the folder in one transaction, then reload the vault, publish the
    /// logins, and sync, as a save does. The paste is dropped on success. Nil on failure, with
    /// the core's message in `error`.
    func add(in vault: VaultModel) async -> [PastedItem]? {
        guard !isAdding else { return nil }
        isAdding = true
        defer { isAdding = false }
        // The rows that the owner saw and checked. When the text changed since, the detection
        // below may give other rows: then nothing is added, and the owner checks the new rows.
        let shown = rows.map { RowIdentity(index: $0.id, key: $0.key) }
        await detectNow()
        guard rows.map({ RowIdentity(index: $0.id, key: $0.key) }) == shown else {
            if !rows.isEmpty { error = Self.rowsChanged }
            return nil
        }
        guard keptCount > 0 else {
            error = rows.isEmpty ? (detectError ?? Self.nothingFound) : "Pick at least one credential."
            return nil
        }
        do {
            let added = try await service.addPasted(text: text, folder: folder, pick: pick, titles: titles)
            error = nil
            clear()
            await vault.didImport()
            return added
        } catch {
            self.error = error.localizedDescription
            // "The folder is gone": the menu shows the folders that are there.
            if (error as? VaultError)?.code == .notFound { await loadFolders() }
            return nil
        }
    }

    /// Follow the drops of revealed values (`VaultModel.revealEpoch`): the app went to the
    /// background, left the screen for a moment, or locked. The paste goes with the revealed
    /// values, and the sheet stays open, empty. The first call only notes the epoch.
    func follow(revealEpoch: Int) {
        defer { seenEpoch = revealEpoch }
        guard let seenEpoch, seenEpoch != revealEpoch else { return }
        clear()
    }

    /// Drop the paste and the rows. Each way out of the sheet calls it.
    func clear() {
        detectTask?.cancel()
        detectTask = nil
        text = ""
        rows = []
        error = nil
        detectError = nil
    }
}

/// A place of a folder menu (ADR 0026 §5): the top level, or a folder with its depth.
struct FolderMenuChoice: Identifiable, Hashable {
    /// The folder UUID; nil for the top level.
    let id: String?
    let name: String
    /// 0 for a top-level folder and for "No folder".
    let depth: Int
}

/// The folder menu of "New Credential" and of the editor. The order, the levels, and the labels
/// come from `FolderTree`, as in the folder picker.
enum FolderMenu {
    static let noFolder = FolderTree.noFolder

    /// "No folder", then each folder in tree order (`FolderTree.choices`).
    static func choices(_ folders: [Folder]) -> [FolderMenuChoice] {
        [FolderMenuChoice(id: nil, name: noFolder, depth: 0)]
            + FolderTree(folders).choices().map { choice in
                FolderMenuChoice(id: choice.folder.uuid, name: choice.folder.name, depth: choice.level)
            }
    }

    /// "Acme › Billing", as the Mac's path label; "No folder" for nil or a folder that is gone
    /// (`FolderTree.pathLabel`).
    static func label(_ folders: [Folder], _ uuid: String?) -> String {
        FolderTree(folders).pathLabel(uuid)
    }
}
