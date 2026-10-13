import ApassyVaultKit
import Foundation

/// The credentials of one folder in "All credentials": a group with its header.
struct FolderGroup: Identifiable, Equatable, Sendable {
    /// The folder UUID; nil for the credentials without a folder.
    let folder: String?
    /// "Acme › Billing", or `FolderTree.noFolder`.
    let title: String
    let items: [ItemRow]

    var id: String { folder ?? "" }
}

/// A folder in a picker: indented by its level.
struct FolderChoice: Identifiable, Equatable, Sendable {
    let folder: Folder
    /// 0 at the top level.
    let level: Int

    var id: String { folder.uuid }
}

/// The folders of the vault as the screens use them (ADR 0026 §5), as the Mac's `FolderTree`:
/// the subfolders of a folder, its path, the credentials in it, and the groups of "All
/// credentials". No call to the core.
struct FolderTree: Equatable, Sendable {
    /// The name of the place without a folder: the header of its group and the first choice of a
    /// folder picker.
    static let noFolder = "No folder"

    /// Depth first, in the order of the core.
    let folders: [Folder]

    init(_ folders: [Folder] = []) {
        self.folders = folders
    }

    func folder(_ uuid: String?) -> Folder? {
        guard let uuid else { return nil }
        return folders.first { $0.uuid == uuid }
    }

    /// The folders right under `parent` (nil: the top level).
    func children(of parent: String?) -> [Folder] {
        folders.children(of: parent)
    }

    /// The names from the top level to `uuid`.
    func path(_ uuid: String?) -> [String] {
        folders.path(to: uuid)
    }

    /// "Acme › Billing", or "No folder" for nil and for a folder that is gone.
    func pathLabel(_ uuid: String?) -> String {
        let names = path(uuid)
        return names.isEmpty ? Self.noFolder : names.joined(separator: " › ")
    }

    /// The level of a folder: 0 at the top level.
    func level(_ uuid: String) -> Int {
        max(0, path(uuid).count - 1)
    }

    /// The folder and every folder below it.
    func subtree(_ uuid: String) -> Set<String> {
        var found: Set<String> = [uuid]
        var grew = true
        while grew {
            grew = false
            for folder in folders where folder.parent.map(found.contains) == true && !found.contains(folder.uuid) {
                found.insert(folder.uuid)
                grew = true
            }
        }
        return found
    }

    /// The folder of a credential, as the screens see it: nil at the top level, and for a folder
    /// that is gone (another device deleted it; the core reads it as the top level too).
    func folder(of item: ItemRow) -> String? {
        guard let uuid = item.folder, folder(uuid) != nil else { return nil }
        return uuid
    }

    /// The credentials that are not archived in the folder and its subfolders, as the Mac lists a
    /// folder.
    func count(_ uuid: String, in items: [ItemRow]) -> Int {
        let inside = subtree(uuid)
        return items.count(where: { !$0.archived && folder(of: $0).map(inside.contains) == true })
    }

    /// The credentials right in `uuid` (nil: without a folder) that are not archived, A–Z.
    func items(in uuid: String?, of items: [ItemRow]) -> [ItemRow] {
        VaultQuery.sorted(items.filter { !$0.archived && folder(of: $0) == uuid }, by: .title)
    }

    /// The groups of "All credentials", as on the Mac: the credentials without a folder first,
    /// then each folder by its path. Each group A–Z; an empty folder has no group.
    func groups(_ items: [ItemRow]) -> [FolderGroup] {
        let byFolder = Dictionary(grouping: items) { folder(of: $0) }
        return byFolder.keys
            .map { (folder: $0, title: pathLabel($0)) }
            .sorted { a, b in
                if (a.folder == nil) != (b.folder == nil) { return a.folder == nil }
                let order = a.title.localizedStandardCompare(b.title)
                return order == .orderedSame ? (a.folder ?? "") < (b.folder ?? "") : order == .orderedAscending
            }
            .map { FolderGroup(folder: $0.folder, title: $0.title, items: VaultQuery.sorted(byFolder[$0.folder] ?? [], by: .title)) }
    }

    /// The names of the subfolders of `uuid`, for the line under it: "Acme · Apassy".
    func childNames(_ uuid: String) -> String {
        children(of: uuid).map(\.name).joined(separator: " · ")
    }

    /// Every folder in tree order with its level, without `excluded` (a folder that moves cannot
    /// go into itself or one of its subfolders).
    func choices(excluding excluded: Set<String> = []) -> [FolderChoice] {
        func level(_ parent: String?, _ depth: Int) -> [FolderChoice] {
            children(of: parent)
                .filter { !excluded.contains($0.uuid) }
                .flatMap { [FolderChoice(folder: $0, level: depth)] + level($0.uuid, depth + 1) }
        }
        return level(nil, 0)
    }

    /// The places a folder can move to: the top level and each folder outside its subtree whose
    /// level leaves room for the folder and the levels below it (`Folder.maxDepth`).
    func moveTargets(for uuid: String) -> [FolderChoice] {
        let height = height(uuid)
        return choices(excluding: subtree(uuid)).filter { $0.level + 1 + height <= Folder.maxDepth }
    }

    /// Whether a new folder fits inside `parent` (nil: the top level).
    func canHoldSubfolder(_ parent: String?) -> Bool {
        path(parent).count < Folder.maxDepth
    }

    /// The levels of a folder and the folders below it, the folder counting 1.
    private func height(_ uuid: String, seen: Set<String> = []) -> Int {
        guard !seen.contains(uuid) else { return 0 }
        let seen = seen.union([uuid])
        return 1 + (children(of: uuid).map { height($0.uuid, seen: seen) }.max() ?? 0)
    }
}
