import ApassyVaultKit
import Foundation
import Testing
@testable import ApassyVaultCore

/// This adapter is for synthetic tests only. Production rejects local file URLs.
final class LocalICloudFiles: ICloudFileAccess, @unchecked Sendable {
    private let lock = NSLock()
    var failBookmark = false
    var stale = false
    var failSnapshot = false
    var snapshotError: VaultError.Code?
    var failPublication = false
    var changeBeforePublication = false
    var beforePublication: (@Sendable () -> Void)?
    var conflicts: [URL] = []
    private(set) var resolved: [String] = []
    private var bookmarkCount = 0
    private var snapshotCount = 0
    private var publicationCount = 0
    var bookmarks: Int { lock.withLock { bookmarkCount } }
    var snapshots: Int { lock.withLock { snapshotCount } }
    var publications: Int { lock.withLock { publicationCount } }

    func makeBookmark(for url: URL) throws -> Data {
        if failBookmark { throw VaultError(.io, "No file access.") }
        lock.withLock { bookmarkCount += 1 }
        return Data(url.path.utf8)
    }
    func resolveBookmark(_ data: Data) throws -> URL {
        if stale { throw VaultError(.io, "Select the file again.") }
        return URL(fileURLWithPath: String(decoding: data, as: UTF8.self))
    }
    func hasChanged(at url: URL, previousHash: String?) throws -> Bool {
        if !conflicts.isEmpty { return true }
        return try CoordinatedICloudFileAccess.hash(url) != previousHash
    }
    func snapshot(from url: URL, to destination: URL) throws {
        if let snapshotError { throw VaultError(snapshotError, "Provider conflict.") }
        if failSnapshot { throw VaultError(.io, "No file access.") }
        lock.withLock { snapshotCount += 1 }
        try FileManager.default.copyItem(at: url, to: destination)
    }
    func snapshotForSync(from url: URL, to destination: URL) throws -> [ICloudConflictSnapshot] {
        try snapshot(from: url, to: destination)
        return try conflicts.enumerated().map { index, source in
            let copy = destination.deletingLastPathComponent().appendingPathComponent("conflict-\(index)")
            try CoordinatedICloudFileAccess.copySnapshot(from: source, to: copy)
            return ICloudConflictSnapshot(url: copy, sha256: try CoordinatedICloudFileAccess.hash(copy))
        }
    }
    func publish(from source: URL, to url: URL, expectedInputHash: String, outputHash: String,
        authorize: @Sendable (@Sendable () throws -> Void) throws -> Void) throws -> Bool {
        try publishForSync(from: source, to: url, expectedInputHash: expectedInputHash,
                           expectedConflictHashes: [], outputHash: outputHash, authorize: authorize)
    }
    func publishForSync(from source: URL, to url: URL, expectedInputHash: String,
        expectedConflictHashes: [String], outputHash: String,
        authorize: @Sendable (@Sendable () throws -> Void) throws -> Void) throws -> Bool {
        lock.withLock { publicationCount += 1 }
        beforePublication?()
        if failPublication { throw VaultError(.io, "The file write failed.") }
        let change = lock.withLock {
            let result = changeBeforePublication
            changeBeforePublication = false
            return result
        }
        if change { try Data("new remote ciphertext".utf8).write(to: url) }
        let hashes = try conflicts.map { try CoordinatedICloudFileAccess.hash($0) }
        guard hashes.sorted() == expectedConflictHashes.sorted() else { return false }
        guard try CoordinatedICloudFileAccess.hash(url) == expectedInputHash else { return false }
        #expect(try CoordinatedICloudFileAccess.hash(source) == outputHash)
        try authorize {
            try Data(contentsOf: source).write(to: url, options: .atomic)
            resolved += hashes
            conflicts = []
        }
        return true
    }
}

actor TransferProbe {
    var prepares = 0
    var completes = 0
    var seen: [String] = []
    var keys: [String] = []
    func recordKey(_ key: String?) { keys.append(key ?? "local-key") }
    func prepared(input: URL, output: URL, write: Bool = true, rekey: Bool = false) throws -> ICloudPrepared {
        prepares += 1
        seen.append(String(decoding: try Data(contentsOf: input), as: UTF8.self))
        #expect(input.lastPathComponent == "input" || input.lastPathComponent.hasPrefix("conflict-"))
        #expect(input.deletingLastPathComponent().deletingLastPathComponent().lastPathComponent == "icloud-transfer")
        let hash = try CoordinatedICloudFileAccess.hash(input)
        if write { try Data("merged encrypted output".utf8).write(to: output) }
        return ICloudPrepared(token: "t\(prepares)", inputSHA256: hash,
            outputSHA256: write ? try CoordinatedICloudFileAccess.hash(output) : nil,
            writeRequired: write, rekeyed: rekey)
    }
    func complete() -> SyncStatus {
        completes += 1
        return SyncStatus(enabled: true, state: .ok, message: "core", version: UInt64(completes),
            lastSyncAt: 1, pushed: true, merged: nil)
    }
}

private struct TransferFixture: Sendable {
    let directory: URL
    let provider: URL
    let files = LocalICloudFiles()
    let session = ICloudSession()
    let transfer: ICloudVaultTransfer
    init() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("apassy-cloud-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        provider = directory.appendingPathComponent("provider.apassy")
        try Data("initial encrypted data".utf8).write(to: provider)
        transfer = ICloudVaultTransfer(directory: directory, files: files, session: session)
    }
    func register() async throws {
        _ = try await transfer.importVault(url: provider, name: "Personal", passphrase: "synthetic",
            epoch: session.capture(), importer: { _, name, _ in
                VaultEntry(id: "test", name: name, relayURL: nil, teamID: nil, deviceID: nil, addedAt: 0, syncSource: "icloud")
            }, rollback: { _ in Issue.record("unexpected rollback") })
    }
    func cleanup() { try? FileManager.default.removeItem(at: directory) }
    func addConflict(_ value: String = "other encrypted version") throws -> URL {
        let url = directory.appendingPathComponent("version-\(UUID().uuidString).apassy")
        try Data(value.utf8).write(to: url)
        files.conflicts.append(url)
        return url
    }
    func archivedHashes() throws -> Set<String> {
        let root = directory.appendingPathComponent("icloud-recovery")
        guard FileManager.default.fileExists(atPath: root.path) else { return [] }
        let urls = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)!
        return Set(try urls.compactMap { $0 as? URL }.filter { $0.pathExtension == "apassy" }
            .map { try CoordinatedICloudFileAccess.hash($0) })
    }
}

@Suite struct ICloudTransferTests {
    @Test func compareAndSwapRetriesFromANewSnapshot() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        fixture.files.changeBeforePublication = true
        let probe = TransferProbe()
        let result = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
            prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output) },
            complete: { _, _ in await probe.complete() })
        #expect(result.status.state == .ok)
        #expect(await probe.prepares == 2)
        #expect(await probe.completes == 1)
        #expect(fixture.files.bookmarks == 2) // import and authenticated provider refresh
        #expect(await probe.seen == ["initial encrypted data", "new remote ciphertext"])
        #expect(String(decoding: try Data(contentsOf: fixture.provider), as: UTF8.self) == "merged encrypted output")
    }

    @Test func failedWriteDoesNotCompleteAndKeepsProvider() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        fixture.files.failPublication = true
        let probe = TransferProbe()
        await #expect(throws: VaultError.self) {
            _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
                prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output) },
                complete: { _, _ in await probe.complete() })
        }
        #expect(await probe.completes == 0)
        #expect(await fixture.transfer.status("test").state == .offline)
        #expect(String(decoding: try Data(contentsOf: fixture.provider), as: UTF8.self) == "initial encrypted data")
    }

    @Test func noWriteChecksFreshSnapshotAndDoesNotPublish() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        let probe = TransferProbe()
        _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
            prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output, write: false) },
            complete: { _, _ in await probe.complete() })
        #expect(fixture.files.publications == 0)
        #expect(fixture.files.snapshots == 3) // import, input, freshness check
        #expect(await probe.completes == 1)
    }

    @Test func staleBookmarkStopsBeforeCorePrepare() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        fixture.files.stale = true
        let probe = TransferProbe()
        await #expect(throws: VaultError.self) {
            _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
                prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output) },
                complete: { _, _ in await probe.complete() })
        }
        #expect(await probe.prepares == 0)
    }

    @Test func sessionChangeStopsPublication() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        fixture.files.beforePublication = { fixture.session.invalidate() }
        let probe = TransferProbe()
        await #expect(throws: VaultError.self) {
            _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
                prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output) },
                complete: { _, _ in await probe.complete() })
        }
        #expect(await probe.completes == 0)
        #expect(String(decoding: try Data(contentsOf: fixture.provider), as: UTF8.self) == "initial encrypted data")
    }

    @Test func acceptedPassphraseSurvivesProviderWriteFailure() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        fixture.files.failPublication = true
        let probe = TransferProbe()
        let result = try await fixture.transfer.sync(id: "test", passphrase: "new synthetic passphrase",
            epoch: fixture.session.capture(),
            prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output, rekey: true) },
            complete: { _, _ in await probe.complete() })
        #expect(result.rekeyed)
        #expect(result.status.state == .offline)
        #expect(await probe.completes == 0)
    }

    @Test func reconnectDoesNotReplaceBookmarkBeforeIdentityCheck() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        let wrong = fixture.directory.appendingPathComponent("wrong.apassy")
        try Data("wrong vault".utf8).write(to: wrong)
        await #expect(throws: VaultError.self) {
            try await fixture.transfer.reconnect(url: wrong, id: "test", epoch: fixture.session.capture(),
                prepare: { _, _, _, _ in throw VaultError(.safetyMismatch, "Wrong vault.") })
        }
        let probe = TransferProbe()
        _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
            prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output, write: false) },
            complete: { _, _ in await probe.complete() })
        #expect(await probe.seen == ["initial encrypted data"])
    }

    @Test func removeOnlyDeletesBookmark() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        await fixture.transfer.remove("test")
        #expect(FileManager.default.fileExists(atPath: fixture.provider.path))
    }

    @Test func bookmarkFailureStopsImportBeforeCore() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        fixture.files.failBookmark = true
        await #expect(throws: VaultError.self) { try await fixture.register() }
        #expect(fixture.files.snapshots == 0)
    }
    @Test func prepareErrorReportsAcceptedPassphrase() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        let result = try await fixture.transfer.sync(id: "test", passphrase: "new synthetic passphrase",
            epoch: fixture.session.capture(),
            prepare: { _, _, _, _ in throw VaultError(.io, "Output failed.", rekeyed: true) },
            complete: { _, _ in Issue.record("must not complete"); return await TransferProbe().complete() })
        #expect(result.rekeyed)
        #expect(result.status.state == .offline)
    }

    @Test func pendingStateSurvivesProviderPublication() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        let probe = TransferProbe()
        let result = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
            prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output) },
            complete: { _, _ in
                var status = await probe.complete()
                status.state = .pending
                status.message = "New local changes need sync."
                return status
            })
        #expect(result.status.state == .pending)
        #expect(result.status.message.contains("New local changes"))
    }

    @Test func aFailedPushOutsideTheLoopMakesTheWaitSyncAgain() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        let probe = TransferProbe()
        _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
            prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output, write: false) },
            complete: { _, _ in await probe.complete() })
        #expect(!(try await fixture.transfer.wait(id: "test", timeout: 1, epoch: fixture.session.capture())))
        // The push of a change on this iPhone fails (the sync 2 s after a save runs outside the
        // loop). The iCloud file stays as it was, so only the failed sync tells the loop.
        fixture.files.failPublication = true
        await #expect(throws: VaultError.self) {
            _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
                prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output) },
                complete: { _, _ in await probe.complete() })
        }
        fixture.files.failPublication = false
        #expect(try await fixture.transfer.wait(id: "test", timeout: 1, epoch: fixture.session.capture()))
    }

    @Test func largeProviderSnapshotStopsBeforeCopy() throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        let handle = try FileHandle(forWritingTo: fixture.provider)
        try handle.truncate(atOffset: CoordinatedICloudFileAccess.maximumSnapshotBytes + 1)
        try handle.close()
        let destination = fixture.directory.appendingPathComponent("input")
        do {
            try CoordinatedICloudFileAccess.copySnapshot(from: fixture.provider, to: destination)
            Issue.record("copied an oversized provider file")
        } catch let error as VaultError { #expect(error.code == .tooLarge) }
        #expect(!FileManager.default.fileExists(atPath: destination.path))
    }

    @Test func repeatedProviderChangesStopAfterThreeAttempts() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        fixture.files.beforePublication = {
            try? Data(UUID().uuidString.utf8).write(to: fixture.provider)
        }
        let probe = TransferProbe()
        do {
            _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
                prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output) },
                complete: { _, _ in await probe.complete() })
            Issue.record("sync did not stop after repeated provider changes")
        } catch let error as VaultError { #expect(error.code == .busy) }
        #expect(await probe.prepares == 3)
        #expect(await probe.completes == 0)
        #expect(fixture.files.publications == 3)
    }

    @Test func providerConflictStopsBeforeCoreAndKeepsFile() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        fixture.files.snapshotError = .conflict
        let probe = TransferProbe()
        await #expect(throws: VaultError.self) {
            _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
                prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output) },
                complete: { _, _ in await probe.complete() })
        }
        #expect(await probe.prepares == 0)
        #expect(fixture.files.publications == 0)
        #expect(await fixture.transfer.status("test").state == .error)
        #expect(String(decoding: try Data(contentsOf: fixture.provider), as: UTF8.self) == "initial encrypted data")
    }

    @Test func outputHashFailureStopsBeforePublication() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        let probe = TransferProbe()
        await #expect(throws: VaultError.self) {
            _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
                prepare: { _, input, output, _ in
                    let prepared = try await probe.prepared(input: input, output: output)
                    try Data("changed output".utf8).write(to: output)
                    return prepared
                }, complete: { _, _ in await probe.complete() })
        }
        #expect(await probe.completes == 0)
        #expect(fixture.files.publications == 0)
        #expect(await fixture.transfer.status("test").state == .damaged)
    }

    @Test func conflictsAreAllPreparedThenCurrentAndArchivedBeforeResolution() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        let first = try fixture.addConflict()
        let second = try fixture.addConflict("third encrypted version")
        let originals = try [fixture.provider, first, second].map { try CoordinatedICloudFileAccess.hash($0) }
        fixture.files.beforePublication = { #expect((try? fixture.archivedHashes()) == Set(originals)) }
        let probe = TransferProbe()
        _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
            prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output) },
            complete: { _, _ in await probe.complete() })
        #expect(await probe.seen == ["other encrypted version", "third encrypted version", "initial encrypted data"])
        #expect(await probe.completes == 1)
        #expect(fixture.files.resolved.count == 2)
        #expect(try fixture.archivedHashes() == Set(originals))
        #expect(try CoordinatedICloudFileAccess.hash(first) == originals[1])
        #expect(try CoordinatedICloudFileAccess.hash(second) == originals[2])
    }

    @Test func unchangedContentStillResolvesAuthenticatedConflicts() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        _ = try fixture.addConflict("initial encrypted data")
        let probe = TransferProbe()
        _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
            prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output, write: false) },
            complete: { _, _ in await probe.complete() })
        #expect(fixture.files.resolved.count == 1)
        #expect(fixture.files.publications == 1)
        #expect(try fixture.archivedHashes().count == 1)
        #expect(String(decoding: try Data(contentsOf: fixture.provider), as: UTF8.self) == "initial encrypted data")
    }

    @Test func changedConflictSetRetriesAndAuthenticatesNewVersion() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        let conflict = try fixture.addConflict()
        fixture.files.beforePublication = {
            try? Data("new conflict ciphertext".utf8).write(to: conflict)
        }
        let probe = TransferProbe()
        _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
            prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output) },
            complete: { _, _ in await probe.complete() })
        #expect(await probe.seen == ["other encrypted version", "initial encrypted data", "new conflict ciphertext", "initial encrypted data"])
        #expect(fixture.files.publications == 2)
        #expect(fixture.files.resolved == [try CoordinatedICloudFileAccess.hash(conflict)])
        #expect(await probe.completes == 1)
        #expect(try fixture.archivedHashes().count == 3)
    }

    @Test(arguments: ["authentication", "archive", "publication", "session"])
    func conflictFailureKeepsEveryProviderVersion(stage: String) async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        let conflict = try fixture.addConflict()
        let originals = try [fixture.provider, conflict].map { try CoordinatedICloudFileAccess.hash($0) }
        if stage == "archive" {
            try Data("block archive".utf8).write(to: fixture.directory.appendingPathComponent("icloud-recovery"))
        }
        if stage == "publication" { fixture.files.failPublication = true }
        if stage == "session" { fixture.files.beforePublication = { fixture.session.invalidate() } }
        let probe = TransferProbe()
        await #expect(throws: (any Error).self) {
            _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
                prepare: { _, input, output, _ in
                    if stage == "authentication" { throw VaultError(.safetyMismatch, "Other vault.") }
                    return try await probe.prepared(input: input, output: output)
                }, complete: { _, _ in await probe.complete() })
        }
        #expect(fixture.files.resolved.isEmpty)
        #expect(fixture.files.conflicts == [conflict])
        #expect(try [fixture.provider, conflict].map { try CoordinatedICloudFileAccess.hash($0) } == originals)
        #expect(await probe.completes == 0)
    }

    @Test func newConflictArrivingBeforePublicationIsNotResolvedUntilAuthenticated() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        _ = try fixture.addConflict()
        fixture.files.beforePublication = {
            if fixture.files.conflicts.count == 1 { _ = try? fixture.addConflict("arriving encrypted version") }
        }
        let probe = TransferProbe()
        _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
            prepare: { _, input, output, _ in
                #expect(fixture.files.resolved.isEmpty)
                return try await probe.prepared(input: input, output: output)
            }, complete: { _, _ in await probe.complete() })
        #expect(await probe.seen == ["other encrypted version", "initial encrypted data",
                                   "other encrypted version", "arriving encrypted version", "initial encrypted data"])
        #expect(fixture.files.publications == 2)
        #expect(fixture.files.resolved.count == 2)
        #expect(await probe.completes == 1)
    }

    @Test(arguments: [false, true])
    func conflictTriesLocalKeyBeforeSuppliedPassphrase(needsNewKey: Bool) async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        _ = try fixture.addConflict()
        let probe = TransferProbe()
        let result = try await fixture.transfer.sync(id: "test", passphrase: "new-key", epoch: fixture.session.capture(),
            prepare: { _, input, output, key in
                await probe.recordKey(key)
                let conflict = input.lastPathComponent.hasPrefix("conflict-")
                if conflict && needsNewKey && key == nil {
                    throw VaultError(.needsPassphrase, "Needs new key.")
                }
                return try await probe.prepared(input: input, output: output,
                                                rekey: conflict && needsNewKey && key != nil)
            }, complete: { _, _ in await probe.complete() })
        #expect(await probe.keys == (needsNewKey ? ["local-key", "new-key", "new-key"] : ["local-key", "new-key"]))
        #expect(result.rekeyed == needsNewKey)
        #expect(fixture.files.resolved.count == 1)
    }

    @Test(arguments: ["conflict", "current"], [false, true])
    func unsupportedFormatIdentifiesSnapshotAndPreservesError(source: String, rekeyed: Bool) async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        _ = try fixture.addConflict("supported encrypted conflict")
        if source == "conflict" { _ = try fixture.addConflict("unsupported encrypted conflict") }
        _ = try fixture.addConflict("later encrypted conflict")
        let versions = [fixture.provider] + fixture.files.conflicts
        let originals = try versions.map { try CoordinatedICloudFileAccess.hash($0) }
        let probe = TransferProbe()
        let expectedMessage = source == "conflict"
            ? "An iCloud conflict copy uses an unsupported or inconsistent vault format. Sync stopped; all iCloud versions are kept."
            : "The current iCloud file uses an unsupported or inconsistent vault format. Sync stopped; all iCloud versions are kept."
        do {
            _ = try await fixture.transfer.sync(id: "test", passphrase: nil, epoch: fixture.session.capture(),
                prepare: { _, input, output, _ in
                    let value = String(decoding: try Data(contentsOf: input), as: UTF8.self)
                    if (source == "current" && input.lastPathComponent == "input") || value == "unsupported encrypted conflict" {
                        throw VaultError(.unsupportedSchema, "Generic version error.", rekeyed: rekeyed)
                    }
                    return try await probe.prepared(input: input, output: output)
                }, complete: { _, _ in await probe.complete() })
            Issue.record("unsupported format must stop sync")
        } catch let error as VaultError {
            #expect(error.code == .unsupportedSchema)
            #expect(error.message == expectedMessage)
            #expect(error.rekeyed == rekeyed)
        }
        let status = await fixture.transfer.status("test")
        #expect(status.state == .error)
        #expect(status.message == expectedMessage)
        #expect(await probe.seen == (source == "conflict"
            ? ["supported encrypted conflict"]
            : ["supported encrypted conflict", "later encrypted conflict"]))
        #expect(fixture.files.publications == 0)
        #expect(fixture.files.resolved.isEmpty)
        #expect(fixture.files.conflicts == Array(versions.dropFirst()))
        #expect(try versions.map { try CoordinatedICloudFileAccess.hash($0) } == originals)
        #expect(await probe.completes == 0)
        #expect(fixture.files.bookmarks == 1)
    }

    @Test(arguments: [false, true])
    func unsupportedConflictFormatAfterPassphraseRetryKeepsRekeyFlag(rekeyed: Bool) async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        let conflict = try fixture.addConflict()
        let originals = try [fixture.provider, conflict].map { try CoordinatedICloudFileAccess.hash($0) }
        let probe = TransferProbe()
        let message = "An iCloud conflict copy uses an unsupported or inconsistent vault format. Sync stopped; all iCloud versions are kept."
        var result: PassphraseChange?
        do {
            result = try await fixture.transfer.sync(id: "test", passphrase: "new synthetic passphrase",
                epoch: fixture.session.capture(), prepare: { _, _, _, key in
                    await probe.recordKey(key)
                    if key == nil { throw VaultError(.needsPassphrase, "Needs new key.") }
                    throw VaultError(.unsupportedSchema, "Generic version error.", rekeyed: rekeyed)
                }, complete: { _, _ in await probe.complete() })
            #expect(rekeyed)
        } catch let error as VaultError {
            #expect(!rekeyed)
            #expect(error.code == .unsupportedSchema)
            #expect(error.message == message)
            #expect(!error.rekeyed)
        }
        if rekeyed {
            #expect(result?.rekeyed == true)
            #expect(result?.status.state == .error)
            #expect(result?.status.message == message)
        }
        #expect(await probe.keys == ["local-key", "new synthetic passphrase"])
        #expect(await fixture.transfer.status("test").state == .error)
        #expect(await fixture.transfer.status("test").message == message)
        #expect(fixture.files.publications == 0)
        #expect(fixture.files.resolved.isEmpty)
        #expect(fixture.files.conflicts == [conflict])
        #expect(try [fixture.provider, conflict].map { try CoordinatedICloudFileAccess.hash($0) } == originals)
        #expect(await probe.completes == 0)
    }

    @Test func unsupportedCurrentFormatPreservesRekeyFromEarlierConflict() async throws {
        let fixture = try TransferFixture()
        defer { fixture.cleanup() }
        try await fixture.register()
        let conflict = try fixture.addConflict()
        let originals = try [fixture.provider, conflict].map { try CoordinatedICloudFileAccess.hash($0) }
        let probe = TransferProbe()
        let result = try await fixture.transfer.sync(id: "test", passphrase: "new synthetic passphrase",
            epoch: fixture.session.capture(), prepare: { _, input, output, _ in
                if input.lastPathComponent == "input" {
                    throw VaultError(.unsupportedSchema, "Generic version error.")
                }
                return try await probe.prepared(input: input, output: output, rekey: true)
            }, complete: { _, _ in await probe.complete() })
        #expect(result.rekeyed)
        #expect(result.status.state == .error)
        #expect(result.status.message == "The current iCloud file uses an unsupported or inconsistent vault format. Sync stopped; all iCloud versions are kept.")
        #expect(fixture.files.publications == 0)
        #expect(fixture.files.resolved.isEmpty)
        #expect(fixture.files.conflicts == [conflict])
        #expect(try [fixture.provider, conflict].map { try CoordinatedICloudFileAccess.hash($0) } == originals)
        #expect(await probe.completes == 0)
    }

}
