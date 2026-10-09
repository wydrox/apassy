import Foundation
import Testing

@testable import ApassyVaultKit

@Suite struct ModelTests {
    @Test func detailDecodesTheRowAndTheFields() throws {
        let json = """
            {"id": 12, "revision": 3, "title": "GitHub", "kind": "login", "subtitle": "octocat",
             "websites": ["https://github.com"], "tags": ["work"], "archived": false, "has_totp": true,
             "conflict_of": null, "added_at": 1791100000, "changed_at": 1791200000, "used_at": null,
             "notes": "n", "fields": [
               {"name": "password", "label": "Password", "secret": true, "value": null, "role": "password", "custom": false},
               {"name": "x_77", "label": "w", "secret": false, "value": "v", "role": "new_role", "custom": true}]}
            """
        let detail = try JSONDecoder().decode(ItemDetail.self, from: Data(json.utf8))
        #expect(detail.row.title == "GitHub")
        #expect(detail.row.hasTotp)
        #expect(detail.fields[0].role == .password)
        #expect(detail.fields[1].role == .other)
        #expect(detail.field(.password)?.label == "Password")
    }

    @Test func previewServiceUnlocksOnlyWithItsPassphrase() async throws {
        let service = PreviewVaultService(unlocked: false)
        await #expect(throws: VaultError.self) { try await service.unlock(passphrase: "wrong", keep: false) }
        try await service.unlock(passphrase: PreviewVaultService.passphrase, keep: false)
        let items = try await service.items(archived: .no)
        #expect(!items.isEmpty)
        #expect(items.allSatisfy { !$0.archived })
    }
}
