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
}
