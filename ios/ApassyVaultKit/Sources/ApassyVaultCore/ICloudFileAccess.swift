import ApassyVaultKit
import CryptoKit
import Foundation

/// The provider boundary. Tests use a local implementation without iCloud access.
public protocol ICloudFileAccess: Sendable {
    func makeBookmark(for url: URL) throws -> Data
    func resolveBookmark(_ data: Data) throws -> URL
    func hasChanged(at url: URL, previousHash: String?) throws -> Bool
    func snapshot(from url: URL, to destination: URL) throws
    /// Return false if the provider changed since the snapshot. Do not write in that case.
    func publish(from source: URL, to url: URL, expectedInputHash: String,
                 outputHash: String, authorize: @Sendable (@Sendable () throws -> Void) throws -> Void) throws -> Bool
}

public struct CoordinatedICloudFileAccess: ICloudFileAccess {
    public init() {}

    private func access<T>(_ url: URL, _ body: () throws -> T) throws -> T {
        guard url.startAccessingSecurityScopedResource() else {
            throw VaultError(.io, "Select the iCloud vault file again to give access to it.")
        }
        defer { url.stopAccessingSecurityScopedResource() }
        return try body()
    }

    private func validate(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isUbiquitousItemKey, .isDirectoryKey, .isSymbolicLinkKey])
        guard values.isUbiquitousItem == true, values.isDirectory != true, values.isSymbolicLink != true else {
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
        try FileManager.default.startDownloadingUbiquitousItem(at: url)
        let deadline = Date().addingTimeInterval(20)
        repeat {
            try Task.checkCancellation()
            var freshURL = url
            freshURL.removeAllCachedResourceValues()
            let values = try freshURL.resourceValues(forKeys: [.ubiquitousItemDownloadingStatusKey, .ubiquitousItemDownloadingErrorKey])
            if values.ubiquitousItemDownloadingError != nil {
                throw VaultError(.io, "iCloud cannot download this file. Try again when iCloud is available.")
            }
            if values.ubiquitousItemDownloadingStatus == .current {
                return
            }
            Thread.sleep(forTimeInterval: 0.2)
        } while Date() < deadline
        throw VaultError(.io, "The iCloud file download did not finish. Try again later.")
    }

    private func noConflicts(_ url: URL) throws {
        guard NSFileVersion.unresolvedConflictVersionsOfItem(at: url)?.isEmpty != false else {
            throw VaultError(.conflict, "iCloud has conflicting file versions. Sync stopped. Keep all versions until you can resolve the conflict on your Mac.")
        }
    }

    public func hasChanged(at url: URL, previousHash: String?) throws -> Bool {
        try access(url) {
            try validate(url)
            var freshURL = url
            freshURL.removeAllCachedResourceValues()
            let values = try freshURL.resourceValues(forKeys: [.ubiquitousItemDownloadingStatusKey,
                                                              .ubiquitousItemDownloadingErrorKey])
            if values.ubiquitousItemDownloadingError != nil {
                throw VaultError(.io, "iCloud cannot download this file. Try again when iCloud is available.")
            }
            if values.ubiquitousItemDownloadingStatus != .current {
                // Start the download, then let the next bounded poll check it.
                try FileManager.default.startDownloadingUbiquitousItem(at: url)
                return false
            }
            var coordinationError: NSError?
            var result: Result<Bool, any Error> = .failure(VaultError(.io, "iCloud did not give access to the file."))
            NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordinationError) { actual in
                result = Result {
                    try noConflicts(actual)
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
        try access(url) {
            try download(url)
            guard try Self.hash(source) == outputHash else {
                throw VaultError(.damaged, "The encrypted output file did not pass its check.")
            }
            var coordinationError: NSError?
            var result: Result<Bool, any Error> = .failure(VaultError(.io, "iCloud did not give access to the file."))
            NSFileCoordinator().coordinate(writingItemAt: url, options: [.forReplacing], error: &coordinationError) { actual in
                result = Result {
                    try noConflicts(actual)
                    guard try Self.hash(actual) == expectedInputHash else { return false }
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
                    }
                    return true
                }
            }
            if let coordinationError { throw coordinationError }
            return try result.get()
        }
    }

    static let maximumSnapshotBytes: UInt64 = 64 * 1024 * 1024

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
