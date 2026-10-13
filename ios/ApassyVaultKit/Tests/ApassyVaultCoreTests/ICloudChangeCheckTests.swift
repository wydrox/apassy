import ApassyVaultKit
import Foundation
import Testing
@testable import ApassyVaultCore

/// Plays iCloud on an iPhone for one file, with a local file as the local copy. A version that
/// the Mac saves waits in iCloud: iOS calls the local copy current, because it is the latest
/// version that this iPhone knows, until an app asks iCloud for the latest version. A download
/// that was asked for ends at the next read of the state.
final class FakeICloud: ICloudItems, @unchecked Sendable {
    private let lock = NSLock()
    private var newer: Data?
    private var downloading = false
    private var requestCount = 0

    /// How many times the code asked iCloud for the latest version.
    var requests: Int { lock.withLock { requestCount } }

    /// The Mac saves a new version of the file in iCloud.
    func macSaves(_ text: String) { lock.withLock { newer = Data(text.utf8) } }

    func startAccessing(_ url: URL) -> Bool { true }
    func stopAccessing(_ url: URL) {}

    func isICloudFile(_ url: URL) throws -> Bool {
        try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true
    }

    func requestLatest(_ url: URL) throws {
        lock.withLock {
            requestCount += 1
            if newer != nil { downloading = true }
        }
    }

    func state(_ url: URL) throws -> ICloudItemState {
        try lock.withLock {
            guard downloading, let data = newer else { return .current }
            try data.write(to: url)
            newer = nil
            downloading = false
            return .downloading
        }
    }
}

/// `CoordinatedICloudFileAccess` over `FakeICloud`. The bookmark is the path.
struct FakeICloudFiles: ICloudFileAccess {
    let coordinated: CoordinatedICloudFileAccess

    init(_ cloud: FakeICloud) { coordinated = CoordinatedICloudFileAccess(items: cloud) }

    func makeBookmark(for url: URL) throws -> Data { Data(url.path.utf8) }
    func resolveBookmark(_ data: Data) throws -> URL { URL(fileURLWithPath: String(decoding: data, as: UTF8.self)) }
    func hasChanged(at url: URL, previousHash: String?) throws -> Bool {
        try coordinated.hasChanged(at: url, previousHash: previousHash)
    }
    func snapshot(from url: URL, to destination: URL) throws {
        try coordinated.snapshot(from: url, to: destination)
    }
    func publish(from source: URL, to url: URL, expectedInputHash: String, outputHash: String,
        authorize: @Sendable (@Sendable () throws -> Void) throws -> Void) throws -> Bool {
        try coordinated.publish(from: source, to: url, expectedInputHash: expectedInputHash,
            outputHash: outputHash, authorize: authorize)
    }
}

/// The check of the sync loop sees a version that the Mac saved, without "Sync now".
@Suite struct ICloudChangeCheckTests {
    private func folder() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("apassy-cloud-check-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func theCheckAsksICloudForTheMacVersionWhileIOSCallsTheLocalCopyCurrent() throws {
        let directory = try folder()
        defer { try? FileManager.default.removeItem(at: directory) }
        let provider = directory.appendingPathComponent("provider.apassy")
        try Data("first version".utf8).write(to: provider)
        let seen = try CoordinatedICloudFileAccess.hash(provider)
        let cloud = FakeICloud()
        let files = CoordinatedICloudFileAccess(items: cloud)
        #expect(!(try files.hasChanged(at: provider, previousHash: seen)))
        cloud.macSaves("version of the Mac")
        // The download of the newer version may end only by the next check of the loop.
        var changed = false
        for _ in 0..<3 where !changed { changed = try files.hasChanged(at: provider, previousHash: seen) }
        #expect(changed)
        #expect(cloud.requests >= 1)
        #expect(String(decoding: try Data(contentsOf: provider), as: UTF8.self) == "version of the Mac")
    }

    @Test func anUnchangedFileIsNoChange() throws {
        let directory = try folder()
        defer { try? FileManager.default.removeItem(at: directory) }
        let provider = directory.appendingPathComponent("provider.apassy")
        try Data("first version".utf8).write(to: provider)
        let files = CoordinatedICloudFileAccess(items: FakeICloud())
        let seen = try CoordinatedICloudFileAccess.hash(provider)
        for _ in 0..<3 { #expect(!(try files.hasChanged(at: provider, previousHash: seen))) }
    }

    @Test func theWaitOfTheLoopSeesTheMacVersionAndTheNextSyncReadsIt() async throws {
        let directory = try folder()
        defer { try? FileManager.default.removeItem(at: directory) }
        let provider = directory.appendingPathComponent("provider.apassy")
        try Data("first version".utf8).write(to: provider)
        let cloud = FakeICloud()
        let session = ICloudSession()
        let transfer = ICloudVaultTransfer(directory: directory, files: FakeICloudFiles(cloud), session: session)
        _ = try await transfer.importVault(url: provider, name: "Personal", passphrase: "synthetic",
            epoch: session.capture(), importer: { _, name, _ in
                VaultEntry(id: "test", name: name, relayURL: nil, teamID: nil, deviceID: nil, addedAt: 0,
                    syncSource: "icloud")
            }, rollback: { _ in Issue.record("unexpected rollback") })
        let probe = TransferProbe()
        _ = try await transfer.sync(id: "test", passphrase: nil, epoch: session.capture(),
            prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output, write: false) },
            complete: { _, _ in await probe.complete() })
        #expect(!(try await transfer.wait(id: "test", timeout: 1, epoch: session.capture())))

        cloud.macSaves("version of the Mac")
        var changed = false
        for _ in 0..<3 where !changed {
            changed = try await transfer.wait(id: "test", timeout: 1, epoch: session.capture())
        }
        #expect(changed)
        _ = try await transfer.sync(id: "test", passphrase: nil, epoch: session.capture(),
            prepare: { _, input, output, _ in try await probe.prepared(input: input, output: output, write: false) },
            complete: { _, _ in await probe.complete() })
        #expect(await probe.seen.last == "version of the Mac")
    }
}
