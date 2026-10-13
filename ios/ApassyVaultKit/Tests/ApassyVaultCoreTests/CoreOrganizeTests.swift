import ApassyVaultKit
import Foundation
import Testing

@testable import ApassyVaultCore

/// Folders, adding by paste, and the options over the real core (macOS slice). The rules are
/// in the core's own tests (`ios/ApassyCore/tests/organize_flow.rs`); here the wire of the Swift
/// side. Synthetic values only.
@Suite struct CoreOrganizeTests {
    private static func fake(_ prefix: String, _ length: Int) -> String {
        prefix + String(String(repeating: "EXAMPLE0", count: length / 8 + 1).prefix(length))
    }

    @Test func foldersPasteAndOptionsRoundTripThroughTheService() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "apassy-core-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let core = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .app)
        _ = try await core.createLocalVault(name: "Personal", passphrase: "synthetic-swift-pass")
        #expect(try await core.folders().isEmpty)

        // Folders.
        let acme = try await core.createFolder(parent: nil, name: "Acme")
        let billing = try await core.createFolder(parent: acme.uuid, name: "Billing")
        let personal = try await core.createFolder(parent: nil, name: "Personal")
        #expect(billing.parent == acme.uuid)
        #expect(billing.count == 0)
        do {
            _ = try await core.createFolder(parent: nil, name: "ACME")
            Issue.record("a taken name made a folder")
        } catch let error as VaultError {
            #expect(error.code == .exists)
        }
        try await core.renameFolder(uuid: personal.uuid, name: "Home")
        try await core.moveFolder(uuid: personal.uuid, parent: acme.uuid)
        try await core.moveFolder(uuid: personal.uuid, parent: nil)
        #expect(try await core.folders().map(\.name) == ["Acme", "Billing", "Home"])

        // Detection: no secret value in the answer.
        let live = Self.fake("sk_live_", 24)
        let github = Self.fake("ghp_", 36)
        let text = "STRIPE_SECRET_KEY=\(live)\nGITHUB_TOKEN=\(github)\nDATABASE_URL=postgres://app:SyntheticDbPw0042@db.example.com/shop"
        let found = try await core.detect(text: text)
        #expect(found.count == 3)
        #expect(found[0].provider == "Stripe")
        #expect(found[0].title == "Stripe live")
        #expect(found[0].environment == .production)
        #expect(found[0].environmentSource == .signal)
        #expect(found[0].cap?.red == true)
        #expect(found[0].fields[0].preview == "sk_live_••••••••")
        #expect(found[1].provider == "GitHub")
        #expect(found.map(\.line) == [1, 2, 3])
        let shown = String(decoding: try JSONEncoder().encode(found), as: UTF8.self)
        for secret in [live, github, "SyntheticDbPw0042"] { #expect(!shown.contains(secret)) }

        // Adding the picked rows to a folder, with a typed title.
        let added = try await core.addPasted(text: text, folder: billing.uuid, pick: [0, 1], titles: [0: "Shop payments"])
        #expect(added.map(\.title) == ["Shop payments", "GitHub token"])
        #expect(added[0].summary == "Shop payments · STRIPE_SECRET_KEY · production")
        let rows = try await core.items(archived: .no)
        let stripe = try #require(rows.first { $0.id == added[0].id })
        #expect(stripe.folder == billing.uuid)
        #expect(stripe.provider == "Stripe")
        #expect(stripe.production == true)
        #expect(try await core.reveal(id: stripe.id, field: "token") == live)
        #expect(try await core.folders().first { $0.uuid == billing.uuid }?.count == 2)

        let detail = try await core.item(id: stripe.id)
        #expect(detail.folderPath == ["Acme", "Billing"])
        #expect(detail.envName == "STRIPE_SECRET_KEY")
        #expect(detail.alwaysAsk == false)
        #expect(detail.environment == .production)
        #expect(detail.environmentSource == .signal)

        // A credential to another folder; the options from the owner.
        try await core.setItemFolder(id: added[1].id, folder: nil)
        #expect(try await core.item(id: added[1].id).folder == nil)
        try await core.setItemOptions(id: added[1].id, alwaysAsk: true, environment: .development)
        let token = try await core.item(id: added[1].id)
        #expect(token.alwaysAsk == true)
        #expect(token.environment == .development)
        #expect(token.environmentSource == .owner)
        #expect(token.row.production == false)

        // Deleting a folder moves its credentials to the parent.
        #expect(try await core.deleteFolder(uuid: billing.uuid) == 1)
        #expect(try await core.item(id: stripe.id).folderPath == ["Acme"])
        do {
            try await core.setItemFolder(id: stripe.id, folder: billing.uuid)
            Issue.record("a deleted folder took a credential")
        } catch let error as VaultError {
            #expect(error.code == .notFound)
        }

        // Locked, the calls are refused.
        try await core.lock()
        for call in [
            { _ = try await core.folders() },
            { _ = try await core.detect(text: live) },
            { _ = try await core.addPasted(text: live, folder: nil) },
            { try await core.setItemOptions(id: stripe.id, alwaysAsk: true, environment: nil) },
        ] as [@Sendable () async throws -> Void] {
            do {
                try await call()
                Issue.record("a locked vault answered")
            } catch let error as VaultError {
                #expect(error.code == .locked)
            }
        }
    }

    @Test func theAutoFillExtensionReadsFoldersOnly() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "apassy-core-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let app = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .app)
        _ = try await app.createLocalVault(name: "Personal", passphrase: "synthetic-swift-pass")
        _ = try await app.createFolder(parent: nil, name: "Acme")
        try await app.suspend()

        let extensionCore = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .autofill)
        try await extensionCore.unlock(passphrase: "synthetic-swift-pass", keep: false)
        #expect(try await extensionCore.folders().map(\.name) == ["Acme"])
        do {
            _ = try await extensionCore.createFolder(parent: nil, name: "Other")
            Issue.record("AutoFill made a folder")
        } catch let error as VaultError {
            #expect(error.code == .notAllowed)
        }
        try await extensionCore.lock()
    }
}
