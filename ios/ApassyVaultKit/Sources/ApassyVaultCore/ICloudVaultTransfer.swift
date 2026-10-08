import ApassyVaultKit
import CryptoKit
import Foundation

/// A short lock guards only local publication and session changes. Provider access
/// and downloads never hold it, so lock and suspend can stop a pending transfer.
final class ICloudSession: @unchecked Sendable {
    private let lock = NSLock()
    private var epoch: UInt64 = 0
    func invalidate() { lock.withLock { epoch &+= 1 } }
    func capture() -> UInt64 { lock.withLock { epoch } }
    func check(_ expected: UInt64) throws {
        try lock.withLock {
            guard expected == epoch else { throw VaultError(.cancelled, "The vault session changed. Try sync again.") }
        }
        try Task.checkCancellation()
    }
    func authorize(_ expected: UInt64, _ operation: @Sendable () throws -> Void) throws {
        try lock.withLock {
            guard expected == epoch else { throw VaultError(.cancelled, "The vault session changed. Try sync again.") }
            try Task.checkCancellation()
            try operation()
        }
    }
}

struct ICloudPrepared: Decodable, Sendable {
    var token: String
    var inputSHA256: String
    var outputSHA256: String?
    var writeRequired: Bool
    var rekeyed: Bool
    enum CodingKeys: String, CodingKey {
        case token, rekeyed
        case inputSHA256 = "input_sha256", outputSHA256 = "output_sha256"
        case writeRequired = "write_required"
    }
}

/// This actor serializes complete cloud transfers, not just their individual steps.
/// Each transfer owns a private directory and the provider does not see plaintext.
actor ICloudVaultTransfer {
    typealias Prepare = @Sendable (String, URL, URL, String?) async throws -> ICloudPrepared
    typealias Complete = @Sendable (String, String) async throws -> SyncStatus
    private let directory: URL
    private let bookmarks: URL
    private let files: any ICloudFileAccess
    private let session: ICloudSession
    private var occupied = false
    private var waiting: [CheckedContinuation<Void, Never>] = []
    private var statuses: [String: SyncStatus] = [:]
    private var inputHashes: [String: String] = [:]

    init(directory: URL, files: any ICloudFileAccess, session: ICloudSession) {
        self.directory = directory.appendingPathComponent("icloud-transfer", isDirectory: true)
        self.bookmarks = directory.appendingPathComponent("icloud-bookmarks", isDirectory: true)
        self.files = files
        self.session = session
    }

    private func enter() async {
        if occupied { await withCheckedContinuation { waiting.append($0) } }
        else { occupied = true }
    }
    private func leave() {
        if waiting.isEmpty { occupied = false }
        else { waiting.removeFirst().resume() }
    }

    private func folder() throws -> URL {
        let folder = directory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        var mutable = folder
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try mutable.setResourceValues(values)
        #if os(iOS)
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: folder.path)
        #endif
        return folder
    }

    private func bookmarkPath(_ id: String) -> URL {
        let key = SHA256.hash(data: Data(id.utf8)).map { String(format: "%02x", $0) }.joined()
        return bookmarks.appendingPathComponent(key)
    }
    private func saveBookmark(_ data: Data, id: String) throws {
        try FileManager.default.createDirectory(at: bookmarks, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        try data.write(to: bookmarkPath(id), options: .atomic)
        try protect(bookmarkPath(id))
    }
    private func url(_ id: String) throws -> URL {
        do { return try files.resolveBookmark(Data(contentsOf: bookmarkPath(id))) }
        catch { throw VaultError(.io, "Select the iCloud vault file again to connect it.") }
    }
    func remove(_ id: String) {
        try? FileManager.default.removeItem(at: bookmarkPath(id))
        statuses[id] = nil
        inputHashes[id] = nil
    }

    func importVault(url: URL, name: String, passphrase: String, epoch: UInt64,
        importer: @Sendable (URL, String, String) async throws -> VaultEntry,
        rollback: @Sendable (String) async -> Void) async throws -> VaultEntry {
        await enter()
        defer { leave() }
        try session.check(epoch)
        let folder = try folder()
        defer { try? FileManager.default.removeItem(at: folder) }
        let input = folder.appendingPathComponent("input")
        let bookmark = try await Task.detached { [files] in
            let data = try files.makeBookmark(for: url)
            try files.snapshot(from: url, to: input)
            return data
        }.value
        try session.check(epoch)
        let vault = try await importer(input, name, passphrase)
        do {
            // Commit only after Rust authenticated the selected encrypted document.
            try saveBookmark(bookmark, id: vault.id)
            statuses[vault.id] = nil
            inputHashes[vault.id] = nil
            try session.check(epoch)
        } catch {
            remove(vault.id)
            await rollback(vault.id)
            throw error
        }
        return vault
    }

    func reconnect(url: URL, id: String, epoch: UInt64, prepare: Prepare) async throws {
        await enter()
        defer { leave() }
        try session.check(epoch)
        let folder = try folder()
        defer { try? FileManager.default.removeItem(at: folder) }
        let input = folder.appendingPathComponent("input")
        let output = folder.appendingPathComponent("output")
        let bookmark = try await Task.detached { [files] in
            let data = try files.makeBookmark(for: url)
            try files.snapshot(from: url, to: input)
            return data
        }.value
        try session.check(epoch)
        _ = try await prepare(id, input, output, nil)
        try session.check(epoch)
        try saveBookmark(bookmark, id: id)
        statuses[id] = nil
        inputHashes[id] = nil
    }

    func status(_ id: String) -> SyncStatus {
        statuses[id] ?? SyncStatus(enabled: true, state: .never, message: "The iCloud file needs sync.",
                                  version: 0, lastSyncAt: nil, pushed: false, merged: nil)
    }

    func sync(id: String, passphrase: String?, epoch: UInt64, prepare: Prepare,
              complete: Complete) async throws -> PassphraseChange {
        await enter()
        defer { leave() }
        var rekeyed = false
        do {
            for _ in 0..<3 {
                try session.check(epoch)
                let folder = try folder()
                defer { try? FileManager.default.removeItem(at: folder) }
                let input = folder.appendingPathComponent("input")
                let output = folder.appendingPathComponent("output")
                let provider = try url(id)
                try await Task.detached { [files] in try files.snapshot(from: provider, to: input) }.value
                try session.check(epoch)
                let prepared = try await prepare(id, input, output, passphrase)
                rekeyed = rekeyed || prepared.rekeyed
                try session.check(epoch)
                // Trust neither the input path nor an unverified Rust output hash.
                guard try CoordinatedICloudFileAccess.hash(input) == prepared.inputSHA256 else {
                    throw VaultError(.damaged, "The encrypted input file did not pass its check.")
                }
                if prepared.writeRequired {
                    guard let outputHash = prepared.outputSHA256 else {
                        throw VaultError(.damaged, "The encrypted output file has no check value.")
                    }
                    guard try CoordinatedICloudFileAccess.hash(output) == outputHash else {
                        throw VaultError(.damaged, "The encrypted output file did not pass its check.")
                    }
                    try protect(output)
                    let didWrite = try await Task.detached { [files, session] in
                        try files.publish(from: output, to: provider, expectedInputHash: prepared.inputSHA256,
                            outputHash: outputHash, authorize: { operation in
                                try session.authorize(epoch, operation)
                            })
                    }.value
                    if !didWrite { continue }
                } else {
                    // No output does not mean the input still exists. Validate a fresh
                    // coordinated snapshot before the core can mark the transfer done.
                    let checkFolder = try self.folder()
                    defer { try? FileManager.default.removeItem(at: checkFolder) }
                    let check = checkFolder.appendingPathComponent("input")
                    try await Task.detached { [files] in try files.snapshot(from: provider, to: check) }.value
                    if try CoordinatedICloudFileAccess.hash(check) != prepared.inputSHA256 { continue }
                }
                try session.check(epoch)
                // Atomic replacement can change the file identity used by bookmarks.
                // Rust already authenticated this document before any bookmark update.
                let refreshed = try await Task.detached { [files] in
                    try files.makeBookmark(for: provider)
                }.value
                try session.check(epoch)
                try saveBookmark(refreshed, id: id)
                var result = try await complete(id, prepared.token)
                try session.check(epoch)
                result.message = result.state == .pending
                    ? "Saved to the iCloud file. New local changes need sync."
                    : "Saved to the iCloud file."
                statuses[id] = result
                inputHashes[id] = prepared.outputSHA256 ?? prepared.inputSHA256
                return PassphraseChange(status: result, rekeyed: rekeyed)
            }
            throw VaultError(.busy, "The iCloud file changed during sync. Try again.")
        } catch {
            rekeyed = rekeyed || (error as? VaultError)?.rekeyed == true
            let code = (error as? VaultError)?.code
            let state: SyncStatus.State
            switch code {
            case .needsPassphrase: state = .needsPassphrase
            case .damaged: state = .damaged
            case .staleCopy: state = .staleCopy
            case .forkedCopy: state = .forkedCopy
            case .busy: state = .busy
            case .conflict, .safetyMismatch, .invalidInput: state = .error
            default: state = .offline
            }
            statuses[id] = SyncStatus(enabled: true, state: state,
                message: (error as? VaultError)?.message ?? "iCloud is not available. Your local vault remains available.",
                version: 0, lastSyncAt: statuses[id]?.lastSyncAt, pushed: false, merged: nil)
            // Rekey is a local change even when the provider write fails. The app
            // must replace its biometric key with the accepted passphrase.
            if passphrase != nil, rekeyed { return PassphraseChange(status: status(id), rekeyed: true) }
            throw error
        }
    }

    func wait(id: String, timeout: Int, epoch: UInt64) async throws -> Bool {
        // Always yield for at least one second. The app's repeated wait loop must not spin.
        try await Task.sleep(for: .seconds(max(1, min(timeout, 5))))
        await enter()
        defer { leave() }
        try session.check(epoch)
        if statuses[id]?.state == .pending { return true }
        let provider = try url(id)
        let previousHash = inputHashes[id]
        let changed = try await Task.detached { [files] in
            try files.hasChanged(at: provider, previousHash: previousHash)
        }.value
        try session.check(epoch)
        return changed
    }
}
