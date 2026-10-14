import ApassyVaultKit
import Foundation
import Testing

@testable import ApassyVaultCore

/// The feed calls over the real core (macOS slice, contract ios-core-v1 section 5.12). The relay
/// flows (sealed feeds, actions, settles) are in the core's own tests
/// (`ios/ApassyCore/tests/feed_flow.rs`, on its fake relay); here the wire of the Swift side.
@Suite struct CoreFeedTests {
    @Test func aVaultWithoutATeamHasNoFeedAndALockDropsIt() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "apassy-core-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let core = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .app)
        _ = try await core.createLocalVault(name: "Personal", passphrase: "synthetic-swift-pass")
        try await core.lock()
        try await core.unlock(passphrase: "synthetic-swift-pass", keep: false)

        // No questions team: no Mac publishes here, and the wait answers at once.
        #expect(try await core.feedList().vaults.isEmpty)
        #expect(try await core.feedWait(timeout: 1) == false)

        let removal = FeedRemoval(
            vaultID: "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c", macDevice: "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d",
            agent: "4", item: "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c", kind: .never, createdAt: 1_789_990_000)
        do {
            _ = try await core.feedActionString(removal, actionID: nil, time: nil)
            Issue.record("an action string was made for a vault that is not on this iPhone")
        } catch let error as VaultError {
            #expect([.noVault, .locked, .notFound].contains(error.code), "\(error)")
        }
        do {
            _ = try await core.feedActionWait(actionID: "sLGys7S1tre4ubq7vL2-vw", vaultID: nil, timeout: 0)
            Issue.record("an action that this process did not post has a state")
        } catch let error as VaultError {
            #expect(error.code == .notFound, "\(error)")
        }

        // A lock drops the feeds with the questions contexts.
        try await core.lock()
        do {
            _ = try await core.feedList()
            Issue.record("the feeds were listed while the vault was locked")
        } catch let error as VaultError {
            #expect(error.code == .locked, "\(error)")
        }
    }

    @Test func autoFillHasNoFeed() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "apassy-core-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let app = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .app)
        _ = try await app.createLocalVault(name: "Personal", passphrase: "synthetic-swift-pass")
        let autofill = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .autofill)
        do {
            _ = try await autofill.feedList()
            Issue.record("AutoFill listed the feeds")
        } catch let error as VaultError {
            #expect(error.code == .notAllowed, "\(error)")
        }
    }
}
