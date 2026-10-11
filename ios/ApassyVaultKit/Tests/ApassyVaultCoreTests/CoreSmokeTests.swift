import ApassyVaultKit
import Foundation
import Testing

@testable import ApassyVaultCore

/// The Swift side over the real core (macOS slice of the XCFramework). Synthetic values.
@Suite struct CoreServiceTests {
    @Test func aLocalVaultRoundTripsThroughTheService() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "apassy-core-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let core = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .app)
        let empty = try await core.info()
        #expect(empty.vaults.isEmpty)
        #expect(empty.schema == 17)

        let vault = try await core.createLocalVault(name: "Personal", passphrase: "synthetic-swift-pass")
        #expect(try await core.info().selectedVault == vault)
        let draft = ItemDraft(
            title: "GitHub", kind: .login, notes: "n", tags: ["work"],
            fields: [
                .named("username", "octocat", secret: false),
                .named("password", "synthetic-Pw-1!", secret: true),
                .detail("Website", "github.com", secret: false),
            ])
        let saved = try await core.save(id: nil, revision: nil, draft: draft)
        let rows = try await core.items(archived: .no)
        #expect(rows.map(\.title) == ["GitHub"])
        #expect(rows[0].websites == ["github.com"])
        let detail = try await core.item(id: saved.id)
        #expect(detail.field(.password)?.value == nil)
        #expect(try await core.reveal(id: saved.id, field: "password") == "synthetic-Pw-1!")
        let fills = try await core.autofillList(domains: ["github.com"])
        #expect(fills.matches.map(\.id) == [saved.id])
        let generated = try await core.generate(GeneratorOptions(style: .pin, length: 8))
        #expect(generated.value.count == 8)

        try await core.lock()
        await #expect(throws: VaultError.self) { try await core.items(archived: .no) }
        do {
            try await core.unlock(passphrase: "synthetic-wrong-pass", keep: false)
            Issue.record("a wrong passphrase unlocked")
        } catch let error as VaultError {
            #expect(error.code == .wrongPassphrase)
        }
        try await core.unlock(passphrase: "synthetic-swift-pass", keep: true)
        try await core.suspend()
        #expect(try await core.resume())
        #expect(try await core.items(archived: .no).count == 1)
    }
}
