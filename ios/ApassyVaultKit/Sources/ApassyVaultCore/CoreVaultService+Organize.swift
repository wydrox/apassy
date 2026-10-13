import ApassyVaultKit
import Foundation

// Folders, adding by paste, and the options of a credential over the core (contract ios-core-v1
// section 5.11). The core refuses the changes in the AutoFill extension; it may read the folders.
extension CoreVaultService {
    private struct Folders: Decodable, Sendable { var folders: [Folder] }
    private struct Created: Decodable, Sendable { var folder: Folder }
    private struct Deleted: Decodable, Sendable { var moved: Int }
    private struct Detection: Decodable, Sendable { var found: [DetectedCredential] }
    private struct Added: Decodable, Sendable { var items: [PastedItem] }

    private static func nullable(_ value: String?) -> Any { value.map { $0 as Any } ?? NSNull() }

    public func folders() async throws -> [Folder] { try await call("folders", as: Folders.self).folders }

    public func createFolder(parent: String?, name: String) async throws -> Folder {
        try await call("folder_create", ["parent": Self.nullable(parent), "name": name], as: Created.self).folder
    }

    public func renameFolder(uuid: String, name: String) async throws {
        try await call("folder_rename", ["uuid": uuid, "name": name])
    }

    public func moveFolder(uuid: String, parent: String?) async throws {
        try await call("folder_move", ["uuid": uuid, "parent": Self.nullable(parent)])
    }

    public func deleteFolder(uuid: String) async throws -> Int {
        try await call("folder_delete", ["uuid": uuid], as: Deleted.self).moved
    }

    public func setItemFolder(id: UInt64, folder: String?) async throws {
        try await call("item_folder_set", ["id": id, "folder": Self.nullable(folder)])
    }

    public func detect(text: String) async throws -> [DetectedCredential] {
        try await call("detect", ["text": text], as: Detection.self).found
    }

    public func addPasted(text: String, folder: String?, pick: [Int]?, titles: [Int: String]) async throws
        -> [PastedItem]
    {
        var params: [String: Any] = ["text": text, "folder": Self.nullable(folder)]
        if let pick { params["pick"] = pick }
        if !titles.isEmpty {
            params["titles"] = titles.sorted { $0.key < $1.key }.map { ["index": $0.key, "title": $0.value] }
        }
        return try await call("add_pasted", params, as: Added.self).items
    }

    public func setItemOptions(id: UInt64, alwaysAsk: Bool?, environment: CredentialEnvironment?) async throws {
        var params: [String: Any] = ["id": id]
        if let alwaysAsk { params["always_ask"] = alwaysAsk }
        if let environment { params["environment"] = environment.rawValue }
        try await call("item_options_set", params)
    }
}
