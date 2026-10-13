import ApassyVaultKit
import CryptoKit
import Foundation

/// Closed encrypted copies, captured together under provider coordination.
public struct ICloudConflictSnapshot: Sendable {
    public let url: URL
    public let sha256: String
    public init(url: URL, sha256: String) { self.url = url; self.sha256 = sha256 }
}

/// The provider boundary. Tests use a local implementation without iCloud access.
public protocol ICloudFileAccess: Sendable {
    func makeBookmark(for url: URL) throws -> Data
    func resolveBookmark(_ data: Data) throws -> URL
    func hasChanged(at url: URL, previousHash: String?) throws -> Bool
    func snapshot(from url: URL, to destination: URL) throws
    func snapshotForSync(from url: URL, to destination: URL) throws -> [ICloudConflictSnapshot]
    /// Return false if the provider changed since the snapshot. Do not write in that case.
    func publish(from source: URL, to url: URL, expectedInputHash: String,
                 outputHash: String, authorize: @Sendable (@Sendable () throws -> Void) throws -> Void) throws -> Bool
    func publishForSync(from source: URL, to url: URL, expectedInputHash: String,
                        expectedConflictHashes: [String], outputHash: String,
                        authorize: @Sendable (@Sendable () throws -> Void) throws -> Void) throws -> Bool
}

public extension ICloudFileAccess {
    func snapshotForSync(from url: URL, to destination: URL) throws -> [ICloudConflictSnapshot] {
        try snapshot(from: url, to: destination)
        return []
    }
    func publishForSync(from source: URL, to url: URL, expectedInputHash: String,
                        expectedConflictHashes: [String], outputHash: String,
                        authorize: @Sendable (@Sendable () throws -> Void) throws -> Void) throws -> Bool {
        guard expectedConflictHashes.isEmpty else {
            throw VaultError(.conflict, "This file provider cannot safely merge conflicting versions.")
        }
        return try publish(from: source, to: url, expectedInputHash: expectedInputHash,
                           outputHash: outputHash, authorize: authorize)
    }
}

/// The state of the local copy of an iCloud file.
enum ICloudItemState: Sendable {
    /// The local copy is the latest version that this device knows.
    case current
    /// iCloud has a newer version, or the download runs.
    case downloading
    /// iCloud cannot download the file.
    case failed
}

/// What iOS does with an iCloud file: the security scope, the kind of item, and the download.
/// Tests play iCloud with a local file.
protocol ICloudItems: Sendable {
    func startAccessing(_ url: URL) -> Bool
    func stopAccessing(_ url: URL)
    /// Whether the URL is a regular file in iCloud Drive, not a folder or a link.
    func isICloudFile(_ url: URL) throws -> Bool
    /// Ask iCloud for the latest version of the file. When the file is on this device already,
    /// iOS syncs the local copy with the version in iCloud.
    func requestLatest(_ url: URL) throws
    /// The state of the local copy, read fresh.
    func state(_ url: URL) throws -> ICloudItemState
}

/// `ICloudItems` of iOS.
struct SystemICloudItems: ICloudItems {
    func startAccessing(_ url: URL) -> Bool { url.startAccessingSecurityScopedResource() }

    func stopAccessing(_ url: URL) { url.stopAccessingSecurityScopedResource() }

    func isICloudFile(_ url: URL) throws -> Bool {
        let values = try url.resourceValues(forKeys: [.isUbiquitousItemKey, .isDirectoryKey, .isSymbolicLinkKey])
        return values.isUbiquitousItem == true && values.isDirectory != true && values.isSymbolicLink != true
    }

    func requestLatest(_ url: URL) throws {
        try FileManager.default.startDownloadingUbiquitousItem(at: url)
    }

    func state(_ url: URL) throws -> ICloudItemState {
        var freshURL = url
        freshURL.removeAllCachedResourceValues()
        let values = try freshURL.resourceValues(forKeys: [.ubiquitousItemDownloadingStatusKey,
                                                          .ubiquitousItemDownloadingErrorKey])
        if values.ubiquitousItemDownloadingError != nil { return .failed }
        return values.ubiquitousItemDownloadingStatus == .current ? .current : .downloading
    }
}

public struct CoordinatedICloudFileAccess: ICloudFileAccess {
    private let items: any ICloudItems

    public init() { items = SystemICloudItems() }

    init(items: any ICloudItems) { self.items = items }

    private func access<T>(_ url: URL, _ body: () throws -> T) throws -> T {
        guard items.startAccessing(url) else {
            throw VaultError(.io, "Select the iCloud vault file again to give access to it.")
        }
        defer { items.stopAccessing(url) }
        return try body()
    }

    private func validate(_ url: URL) throws {
        guard try items.isICloudFile(url) else {
            throw VaultError(.invalidInput, "Select an Apassy vault file in iCloud Drive.")
        }
    }

    public func makeBookmark(for url: URL) throws -> Data {
        try access(url) {
            try validate(url)
            #if os(macOS)
            return try url.bookmarkData(options: [.withSecurityScope], includingResourceValuesForKeys: nil, relativeTo: nil)
            #else
            // iOS obtains the scope from the document picker. withSecurityScope is
            // a macOS-only bookmark option.
            return try url.bookmarkData(options: [.minimalBookmark], includingResourceValuesForKeys: nil, relativeTo: nil)
            #endif
        }
    }

    public func resolveBookmark(_ data: Data) throws -> URL {
        var stale = false
        #if os(macOS)
        let url = try URL(resolvingBookmarkData: data, options: [.withSecurityScope, .withoutUI],
                          relativeTo: nil, bookmarkDataIsStale: &stale)
        #else
        let url = try URL(resolvingBookmarkData: data, options: [.withoutUI],
                          relativeTo: nil, bookmarkDataIsStale: &stale)
        #endif
        guard !stale else { throw VaultError(.io, "Select the iCloud vault file again to connect it.") }
        return url
    }

    private func download(_ url: URL) throws {
        try validate(url)
        try items.requestLatest(url)
        let deadline = Date().addingTimeInterval(20)
        repeat {
            try Task.checkCancellation()
            switch try items.state(url) {
            case .failed:
                throw VaultError(.io, "iCloud cannot download this file. Try again when iCloud is available.")
            case .current:
                return
            case .downloading:
                break
            }
            Thread.sleep(forTimeInterval: 0.2)
        } while Date() < deadline
        throw VaultError(.io, "The iCloud file download did not finish. Try again later.")
    }

    private func noConflicts(_ url: URL) throws {
        guard NSFileVersion.unresolvedConflictVersionsOfItem(at: url)?.isEmpty != false else {
            throw VaultError(.conflict, "iCloud has conflicting file versions. Sync the connected vault to merge them. Keep all versions if this vault is not connected yet.")
        }
    }

    public func hasChanged(at url: URL, previousHash: String?) throws -> Bool {
        try access(url) {
            try validate(url)
            // Ask iCloud for its latest version at each check, as the snapshot of a sync does.
            // "Current" is the latest version that this iPhone knows, and iOS may not learn of
            // a version that the Mac saved until an app asks.
            try items.requestLatest(url)
            switch try items.state(url) {
            case .failed:
                throw VaultError(.io, "iCloud cannot download this file. Try again when iCloud is available.")
            case .downloading:
                // Let the next bounded poll check the download.
                return false
            case .current:
                break
            }
            var coordinationError: NSError?
            var result: Result<Bool, any Error> = .failure(VaultError(.io, "iCloud did not give access to the file."))
            NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { actual in
                result = Result {
                    if NSFileVersion.unresolvedConflictVersionsOfItem(at: actual)?.isEmpty == false { return true }
                    return try Self.hash(actual) != previousHash
                }
            }
            if let coordinationError { throw coordinationError }
            return try result.get()
        }
    }

    public func snapshot(from url: URL, to destination: URL) throws {
        try access(url) {
            try download(url)
            var coordinationError: NSError?
            var result: Result<Void, any Error> = .failure(VaultError(.io, "iCloud did not give access to the file."))
            NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { actual in
                result = Result {
                    try noConflicts(actual)
                    try Self.copySnapshot(from: actual, to: destination)
                }
            }
            if let coordinationError { throw coordinationError }
            try result.get()
        }
    }

    public func publish(from source: URL, to url: URL, expectedInputHash: String,
                        outputHash: String, authorize: @Sendable (@Sendable () throws -> Void) throws -> Void) throws -> Bool {
        try publishForSync(from: source, to: url, expectedInputHash: expectedInputHash,
                           expectedConflictHashes: [], outputHash: outputHash, authorize: authorize)
    }

    public func snapshotForSync(from url: URL, to destination: URL) throws -> [ICloudConflictSnapshot] {
        try access(url) {
            try download(url)
            var coordinationError: NSError?
            var result: Result<[ICloudConflictSnapshot], any Error> = .failure(VaultError(.io, "iCloud did not give access to the file."))
            NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { actual in
                result = Result {
                    let versions = NSFileVersion.unresolvedConflictVersionsOfItem(at: actual) ?? []
                    guard versions.count <= Self.maximumConflictVersions else {
                        throw VaultError(.conflict, "iCloud has too many conflicting versions to merge at once. Keep all versions and resolve them on your Mac.")
                    }
                    try Self.copySnapshot(from: actual, to: destination)
                    return try versions.enumerated().map { index, version in
                        let copy = destination.deletingLastPathComponent().appendingPathComponent("conflict-\(index)")
                        try Self.copySnapshot(from: version.url, to: copy)
                        return ICloudConflictSnapshot(url: copy, sha256: try Self.hash(copy))
                    }
                }
            }
            if let coordinationError { throw coordinationError }
            return try result.get()
        }
    }

    // NSFileVersion objects never leave the synchronous coordinated operation.
    // The wrapper permits capture in the session's synchronous Sendable guard.
    private struct CapturedVersions: @unchecked Sendable {
        let values: [NSFileVersion]
        func resolve() { for version in values { version.isResolved = true } }
    }

    public func publishForSync(from source: URL, to url: URL, expectedInputHash: String,
                               expectedConflictHashes: [String], outputHash: String,
                               authorize: @Sendable (@Sendable () throws -> Void) throws -> Void) throws -> Bool {
        try access(url) {
            try download(url)
            guard try Self.hash(source) == outputHash else {
                throw VaultError(.damaged, "The encrypted output file did not pass its check.")
            }
            var coordinationError: NSError?
            var result: Result<Bool, any Error> = .failure(VaultError(.io, "iCloud did not give access to the file."))
            NSFileCoordinator().coordinate(writingItemAt: url, options: [.forReplacing], error: &coordinationError) { actual in
                result = Result {
                    let versions = NSFileVersion.unresolvedConflictVersionsOfItem(at: actual) ?? []
                    guard versions.count <= Self.maximumConflictVersions else { return false }
                    let hashes = try versions.map { try Self.hash($0.url) }
                    // Compare the complete multiset, including duplicates. A new or
                    // changed version must be authenticated by a fresh prepare.
                    guard hashes.sorted() == expectedConflictHashes.sorted() else { return false }
                    guard try Self.hash(actual) == expectedInputHash else { return false }
                    let captured = CapturedVersions(values: versions)
                    // Ask Foundation for a replacement directory on this volume. A
                    // single-file scope does not permit arbitrary sibling creation.
                    let replacementDirectory = try FileManager.default.url(for: .itemReplacementDirectory,
                        in: .userDomainMask, appropriateFor: actual, create: true)
                    defer { try? FileManager.default.removeItem(at: replacementDirectory) }
                    let replacement = replacementDirectory.appendingPathComponent("vault")
                    try FileManager.default.copyItem(at: source, to: replacement)
                    guard try Self.hash(replacement) == outputHash else {
                        throw VaultError(.damaged, "The encrypted output file did not pass its check.")
                    }
                    try authorize {
                        _ = try FileManager.default.replaceItemAt(actual, withItemAt: replacement)
                        // The caller durably archived every encrypted input and
                        // authenticated all versions before publication. Keep the
                        // provider versions too; never call removeOtherVersions.
                        captured.resolve()
                    }
                    return true
                }
            }
            if let coordinationError { throw coordinationError }
            return try result.get()
        }
    }

    static let maximumSnapshotBytes: UInt64 = 64 * 1024 * 1024
    static let maximumConflictVersions = 8

    static func copySnapshot(from source: URL, to destination: URL) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: source.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular else {
            throw VaultError(.invalidInput, "Select a regular encrypted vault file.")
        }
        guard let size = attributes[.size] as? NSNumber, size.uint64Value <= maximumSnapshotBytes else {
            throw VaultError(.tooLarge, "The encrypted vault file is too large.")
        }
        guard !FileManager.default.fileExists(atPath: destination.path),
              FileManager.default.createFile(atPath: destination.path, contents: nil,
                                              attributes: [.posixPermissions: 0o600]) else {
            throw VaultError(.io, "The private vault snapshot could not be created.")
        }
        do {
            try protect(destination)
            let input = try FileHandle(forReadingFrom: source)
            defer { try? input.close() }
            let output = try FileHandle(forWritingTo: destination)
            defer { try? output.close() }
            var copied: UInt64 = 0
            while let data = try input.read(upToCount: 1024 * 1024), !data.isEmpty {
                copied += UInt64(data.count)
                guard copied <= maximumSnapshotBytes else {
                    throw VaultError(.tooLarge, "The encrypted vault file is too large.")
                }
                try output.write(contentsOf: data)
            }
            try output.synchronize()
        } catch {
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    public static func hash(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hash = SHA256()
        var count: UInt64 = 0
        while let data = try handle.read(upToCount: 1024 * 1024), !data.isEmpty {
            count += UInt64(data.count)
            guard count <= maximumSnapshotBytes else {
                throw VaultError(.tooLarge, "The encrypted vault file is too large.")
            }
            hash.update(data: data)
        }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

func protect(_ url: URL) throws {
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    var mutable = url
    try mutable.setResourceValues(values)
    #if os(iOS)
    try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
    #endif
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}
