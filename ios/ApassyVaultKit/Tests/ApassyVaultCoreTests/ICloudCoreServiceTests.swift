import ApassyVaultKit
import Foundation
import Testing
@testable import ApassyVaultCore

@Suite struct ICloudCoreServiceTests {
    private let passphrase = "synthetic-icloud-passphrase"
    private func root() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("apassy-cloud-core-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
    private func makeDonor(in root: URL) async throws -> (URL, VaultEntry) {
        let directory = root.appendingPathComponent("mac")
        let mac = try CoreVaultService(dataDirectory: directory, deviceName: "Synthetic Mac", role: .app)
        let vault = try await mac.createLocalVault(name: "Personal", passphrase: passphrase)
        _ = try await mac.save(id: nil, revision: nil, draft: ItemDraft(title: "Mac item", kind: .login,
            notes: "", tags: [], fields: [.named("username", "mac", secret: false),
                                       .named("password", "synthetic-mac-secret", secret: true)]))
        try await mac.lock()
        let provider = root.appendingPathComponent("provider.apassy")
        try FileManager.default.copyItem(at: directory.appendingPathComponent("vaults/\(vault.id).apassy"), to: provider)
        return (provider, vault)
    }

    @Test func iCloudImportAndSyncRoundTripThroughRealCore() async throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(at: root) }
        let (provider, donor) = try await makeDonor(in: root)
        let files = LocalICloudFiles()
        let phoneDirectory = root.appendingPathComponent("phone")
        let phone = try CoreVaultService(dataDirectory: phoneDirectory, deviceName: "Synthetic iPhone", role: .app, iCloudFiles: files)
        let imported = try await phone.openICloudVault(url: provider, name: "Personal", passphrase: passphrase)
        #expect(imported.id == donor.id)
        #expect(imported.isICloud)
        #expect(!imported.isRelay)
        #expect(imported.syncs)
        #expect(try await phone.info().selectedVault == imported)
        #expect(try await phone.items(archived: .no).map(\.title) == ["Mac item"])
        _ = try await phone.save(id: nil, revision: nil, draft: ItemDraft(title: "Phone item", kind: .login,
            notes: "", tags: [], fields: [.named("username", "phone", secret: false),
                                       .named("password", "synthetic-phone-secret", secret: true)]))
        let status = try await phone.sync()
        #expect(status.state == .ok)
        #expect(status.message == "Saved to the iCloud file.")
        #expect(files.publications == 1)
        let reader = try CoreVaultService(dataDirectory: root.appendingPathComponent("reader"),
            deviceName: "Synthetic Reader", role: .app, iCloudFiles: LocalICloudFiles())
        _ = try await reader.openICloudVault(url: provider, name: "Personal", passphrase: passphrase)
        #expect(Set(try await reader.items(archived: .no).map(\.title)) == ["Mac item", "Phone item"])
        // A restore cannot publish until the correct encrypted identity is unlocked.
        try await phone.lock()
        try await phone.unlock(passphrase: passphrase, keep: false)
        try await phone.reconnectICloudVault(url: provider, vaultID: imported.id)
        #expect(try await phone.syncStatus().state == .never)
        #expect(try await phone.sync().state == .ok)
        let before = files.publications
        #expect(try await phone.sync().state == .ok)
        #expect(files.publications == before)
        #expect(!(try await phone.syncWait(timeout: 0)))
        try await phone.lock()
        _ = try await phone.removeVault(id: imported.id, force: true)
        #expect(FileManager.default.fileExists(atPath: provider.path))
    }

    @Test func failedBookmarkCommitRollsBackRegistryAndRestoresSelectionLocked() async throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(at: root) }
        let (provider, donor) = try await makeDonor(in: root)
        let directory = root.appendingPathComponent("phone")
        let phone = try CoreVaultService(dataDirectory: directory, deviceName: "Synthetic iPhone", role: .app,
                                        iCloudFiles: LocalICloudFiles())
        let previous = try await phone.createLocalVault(name: "Previous", passphrase: passphrase)
        try Data("blocks directory creation".utf8).write(to: directory.appendingPathComponent("icloud-bookmarks"))
        await #expect(throws: (any Error).self) {
            _ = try await phone.openICloudVault(url: provider, name: "Personal", passphrase: passphrase)
        }
        let info = try await phone.info()
        #expect(info.selected == previous.id)
        #expect(!info.unlocked)
        #expect(!info.vaults.contains { $0.id == donor.id })
        #expect(FileManager.default.fileExists(atPath: provider.path))
    }

    @Test func autoFillCannotStartICloudOperations() async throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(at: root) }
        let (provider, _) = try await makeDonor(in: root)
        let files = LocalICloudFiles()
        let core = try CoreVaultService(dataDirectory: root.appendingPathComponent("autofill"),
            deviceName: "Synthetic AutoFill", role: .autofill, iCloudFiles: files)
        await #expect(throws: VaultError.self) {
            _ = try await core.openICloudVault(url: provider, name: "Personal", passphrase: passphrase)
        }
        await #expect(throws: VaultError.self) { _ = try await core.sync() }
        await #expect(throws: VaultError.self) { _ = try await core.syncWait(timeout: 1) }
        await #expect(throws: VaultError.self) { _ = try await core.takeNewPassphrase(passphrase) }
        #expect(files.snapshots == 0)
        #expect(files.publications == 0)
    }

    @Test func providerVersionsMergeThroughRealCoreAndPreserveConcurrentEdits() async throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(at: root) }
        let (provider, _) = try await makeDonor(in: root)
        let branchFile = root.appendingPathComponent("branch.apassy")
        try FileManager.default.copyItem(at: provider, to: branchFile)
        let files = LocalICloudFiles()
        let phone = try CoreVaultService(dataDirectory: root.appendingPathComponent("phone"),
            deviceName: "Phone", role: .app, iCloudFiles: files)
        _ = try await phone.openICloudVault(url: provider, name: "Personal", passphrase: passphrase)
        let other = try CoreVaultService(dataDirectory: root.appendingPathComponent("other"),
            deviceName: "Other", role: .app, iCloudFiles: LocalICloudFiles())
        _ = try await other.openICloudVault(url: branchFile, name: "Personal", passphrase: passphrase)
        for (service, label) in [(phone, "Phone"), (other, "Other")] {
            let original = try #require(try await service.items(archived: .no).first)
            _ = try await service.save(id: original.id, revision: original.revision,
                draft: ItemDraft(title: "Mac item", kind: .login, notes: "", tags: [],
                    fields: [.named("username", label, secret: false),
                             .named("password", "synthetic-\(label)", secret: true)]))
            _ = try await service.save(id: nil, revision: nil,
                draft: ItemDraft(title: "\(label) addition", kind: .login, notes: "", tags: [],
                    fields: [.named("username", label, secret: false),
                             .named("password", "synthetic-addition", secret: true)]))
        }
        #expect(try await other.sync().state == .ok)
        let originals = try [provider, branchFile].map { try CoordinatedICloudFileAccess.hash($0) }
        files.conflicts = [branchFile]
        #expect(try await phone.sync().state == .ok)
        #expect(files.resolved == [originals[1]])
        #expect(try CoordinatedICloudFileAccess.hash(branchFile) == originals[1])

        let reader = try CoreVaultService(dataDirectory: root.appendingPathComponent("reader"),
            deviceName: "Reader", role: .app, iCloudFiles: LocalICloudFiles())
        _ = try await reader.openICloudVault(url: provider, name: "Personal", passphrase: passphrase)
        let active = try await reader.items(archived: .no)
        #expect(Set(active.map(\.title)) == ["Mac item", "Phone addition", "Other addition"])
        let archived = try await reader.items(archived: .yes)
        let conflictCopy = try #require(archived.first { $0.title.contains("conflict copy") })
        let winner = try #require(active.first { $0.title == "Mac item" })
        let values = try await [reader.reveal(id: winner.id, field: "password"),
                                reader.reveal(id: conflictCopy.id, field: "password")]
        #expect(Set(values) == ["synthetic-Phone", "synthetic-Other"])
        let archive = root.appendingPathComponent("phone/icloud-recovery")
        let recovered = FileManager.default.enumerator(at: archive, includingPropertiesForKeys: nil)!
        let hashes = try recovered.compactMap { $0 as? URL }.filter { $0.pathExtension == "apassy" }
            .map { try CoordinatedICloudFileAccess.hash($0) }
        #expect(Set(hashes) == Set(originals))
    }

    @Test(arguments: [false, true])
    func incompatibleProviderVersionFailsClosedThroughRealCore(malformed: Bool) async throws {
        let root = try root()
        defer { try? FileManager.default.removeItem(at: root) }
        let (provider, _) = try await makeDonor(in: root)
        let files = LocalICloudFiles()
        let phone = try CoreVaultService(dataDirectory: root.appendingPathComponent("phone"),
            deviceName: "Phone", role: .app, iCloudFiles: files)
        _ = try await phone.openICloudVault(url: provider, name: "Personal", passphrase: passphrase)
        let conflict: URL
        if malformed {
            conflict = root.appendingPathComponent("malformed.apassy")
            try Data("not an encrypted vault".utf8).write(to: conflict)
        } else {
            let alienRoot = root.appendingPathComponent("alien")
            try FileManager.default.createDirectory(at: alienRoot, withIntermediateDirectories: true)
            (conflict, _) = try await makeDonor(in: alienRoot)
        }
        files.conflicts = [conflict]
        let originals = try [provider, conflict].map { try CoordinatedICloudFileAccess.hash($0) }
        await #expect(throws: VaultError.self) { _ = try await phone.sync() }
        #expect(files.publications == 0)
        #expect(files.resolved.isEmpty)
        #expect(files.conflicts == [conflict])
        #expect(try [provider, conflict].map { try CoordinatedICloudFileAccess.hash($0) } == originals)
        #expect(try await phone.items(archived: .no).map(\.title) == ["Mac item"])
    }
}
