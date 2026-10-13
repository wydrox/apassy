import Foundation
import Testing

@testable import ApassyVaultKit

/// The models of section 5.11 and the preview vault's folders, paste detection, and options.
/// Synthetic values only.
@Suite struct OrganizeTests {
    private static func fake(_ prefix: String, _ length: Int) -> String {
        prefix + String(String(repeating: "EXAMPLE0", count: length / 8 + 1).prefix(length))
    }

    // MARK: Models

    @Test func anOlderCoreStillDecodes() throws {
        let json = """
            {"id": 12, "revision": 3, "title": "GitHub", "kind": "login", "subtitle": "octocat",
             "websites": [], "tags": [], "archived": false, "has_totp": false,
             "conflict_of": null, "added_at": null, "changed_at": null, "used_at": null,
             "notes": "", "fields": []}
            """
        let detail = try JSONDecoder().decode(ItemDetail.self, from: Data(json.utf8))
        #expect(detail.row.folder == nil)
        #expect(detail.row.provider == nil)
        #expect(detail.row.production == nil)
        #expect(detail.folderPath == nil)
        #expect(detail.envName == nil)
        #expect(detail.alwaysAsk == nil)
        #expect(detail.environment == nil)
        #expect(detail.environmentSource == nil)
    }

    @Test func theNewMembersDecodeAndRoundTrip() throws {
        let json = """
            {"id": 12, "revision": 3, "title": "Stripe live", "kind": "api_key", "subtitle": "",
             "websites": [], "tags": [], "archived": false, "has_totp": false, "has_passkey": false,
             "has_password": false, "conflict_of": null, "added_at": 1, "changed_at": 2, "used_at": null,
             "folder": "f-1", "provider": "Stripe", "production": true,
             "notes": "", "fields": [], "folder_path": ["Acme", "Billing"], "env_name": "STRIPE_SECRET_KEY",
             "always_ask": false, "environment": "production", "environment_source": "signal"}
            """
        let detail = try JSONDecoder().decode(ItemDetail.self, from: Data(json.utf8))
        #expect(detail.folder == "f-1")
        #expect(detail.provider == "Stripe")
        #expect(detail.row.production == true)
        #expect(detail.folderPath == ["Acme", "Billing"])
        #expect(detail.envName == "STRIPE_SECRET_KEY")
        #expect(detail.alwaysAsk == false)
        #expect(detail.environment == .production)
        #expect(detail.environmentSource == .signal)
        let again = try JSONDecoder().decode(ItemDetail.self, from: JSONEncoder().encode(detail))
        #expect(again == detail)
        // An environment of a newer core reads as unknown, not as a failure.
        let newer = json.replacingOccurrences(of: "\"environment\": \"production\"", with: "\"environment\": \"edge\"")
        #expect(try JSONDecoder().decode(ItemDetail.self, from: Data(newer.utf8)).environment == nil)
    }

    @Test func aDetectionDecodesWithTheMacsCapAndLine() throws {
        let json = """
            {"found": [{"index": 0, "title": "Stripe live", "kind": "api_key", "provider": "Stripe",
              "env_name": "STRIPE_SECRET_KEY", "hosts": ["api.stripe.com"], "environment": "production",
              "environment_source": "signal", "risk": "high", "line": null,
              "summary": "Stripe live · STRIPE_SECRET_KEY · production",
              "fields": [{"name": "token", "label": "Token", "secret": true, "preview": "sk_live_••••••••"}]},
             {"index": 1, "title": "Credential", "kind": "custom", "provider": null, "env_name": null,
              "hosts": [], "environment": "production", "environment_source": "default", "risk": "high",
              "line": 2, "summary": "Credential · production", "fields": []}]}
            """
        struct Answer: Decodable { var found: [DetectedCredential] }
        let found = try JSONDecoder().decode(Answer.self, from: Data(json.utf8)).found
        #expect(found[0].cap?.label == "Production")
        #expect(found[0].cap?.red == true)
        #expect(found[0].rowLine == "Stripe · STRIPE_SECRET_KEY · api.stripe.com")
        #expect(found[1].cap == nil)
        #expect(found[1].rowLine == "Other")
        #expect(found[1].line == 2)
    }

    @Test func aFolderPathFollowsTheParents() {
        let folders = PreviewOrganize.sampleFolders
        #expect(folders.path(to: PreviewOrganize.FolderID.billing) == ["Acme", "Billing"])
        #expect(folders.path(to: nil) == [])
        #expect(folders.children(of: nil).map(\.name) == ["Acme", "Personal"])
    }

    // MARK: The preview vault

    @Test func thePreviewHasFoldersProvidersAndOneProductionCredential() async throws {
        let service = PreviewVaultService()
        let folders = try await service.folders()
        #expect(folders.map(\.name) == ["Acme", "Billing", "Personal"])
        #expect(folders[1].parent == folders[0].uuid)
        #expect(folders.allSatisfy { $0.count > 0 })
        let rows = try await service.items(archived: .all)
        #expect(Set(rows.compactMap(\.provider)).isSuperset(of: ["Stripe", "GitHub", "PostgreSQL"]))
        let production = rows.filter { $0.production == true }
        #expect(production.map(\.title) == ["Stripe live key"])
        let stripe = try await service.item(id: production[0].id)
        #expect(stripe.environment == .production)
        #expect(stripe.alwaysAsk == false)
        #expect(stripe.folderPath == ["Acme", "Billing"])
        #expect(stripe.envName == "STRIPE_SECRET_KEY")
        #expect(rows.allSatisfy { $0.production != nil })
    }

    @Test func thePreviewDetectsAndAddsWithoutShowingASecret() async throws {
        let service = PreviewVaultService()
        let live = Self.fake("sk_live_", 24)
        let test = Self.fake("sk_test_", 24)
        let github = Self.fake("ghp_", 36)
        let url = "postgres://app:SyntheticDbPw0042@db.example.com:5432/shop"

        let stripe = try await service.detect(text: live)
        #expect(stripe.count == 1)
        #expect(stripe[0].provider == "Stripe")
        #expect(stripe[0].title == "Stripe live")
        #expect(stripe[0].cap?.red == true)
        #expect(stripe[0].fields[0].preview == "sk_live_••••••••")
        #expect(try await service.detect(text: test)[0].environment == .development)
        #expect(try await service.detect(text: github)[0].provider == "GitHub")
        let db = try await service.detect(text: url)[0]
        #expect(db.provider == "PostgreSQL")
        #expect(db.fields.first { $0.name == "host" }?.preview == "db.example.com:5432")
        #expect(db.fields.first { $0.name == "password" }?.preview == "••••••••")

        let env = "# synthetic\nSTRIPE_SECRET_KEY=\(live)\nGITHUB_TOKEN=\(github)\nDATABASE_URL=\(url)\n"
        let found = try await service.detect(text: env)
        #expect(found.map(\.line) == [2, 3, 4])
        #expect(found.map(\.index) == [0, 1, 2])
        let shown = String(decoding: try JSONEncoder().encode(found), as: UTF8.self)
        for secret in [live, github, "SyntheticDbPw0042"] { #expect(!shown.contains(secret)) }
        #expect(try await service.detect(text: "  ").isEmpty)

        let added = try await service.addPasted(
            text: env, folder: PreviewOrganize.FolderID.acme, pick: [0, 2], titles: [0: " Shop payments "])
        #expect(added.map(\.title) == ["Shop payments", "PostgreSQL database"])
        // The sample Stripe key has STRIPE_SECRET_KEY: the new one gets the automatic name.
        #expect(added[0].summary == "Shop payments · APASSY_ITEM_\(added[0].id) · production")
        let row = try await service.item(id: added[0].id)
        #expect(row.folder == PreviewOrganize.FolderID.acme)
        #expect(row.row.production == true)
        #expect(row.environmentSource == .signal)
        #expect(try await service.reveal(id: added[0].id, field: "token") == live)
        #expect(try await service.item(id: added[1].id).row.production == false)

        let all = try await service.addPasted(text: github, folder: nil)
        #expect(all.map(\.title) == ["GitHub token"])
        #expect(try await service.addPasted(text: github, folder: nil)[0].title == "GitHub token 2")
        await #expect(throws: VaultError.self) { try await service.addPasted(text: "", folder: nil) }
        await #expect(throws: VaultError.self) {
            try await service.addPasted(text: live, folder: nil, pick: [3], titles: [:])
        }
        await #expect(throws: VaultError.self) { try await service.addPasted(text: live, folder: "gone") }
    }

    @Test func thePreviewFoldersFollowTheRulesOfTheCore() async throws {
        let service = PreviewVaultService()
        let acme = PreviewOrganize.FolderID.acme
        let billing = PreviewOrganize.FolderID.billing
        let personal = PreviewOrganize.FolderID.personal
        do {
            _ = try await service.createFolder(parent: nil, name: "acme")
            Issue.record("a taken name made a folder")
        } catch let error as VaultError {
            #expect(error.code == .exists)
        }
        await #expect(throws: VaultError.self) { try await service.createFolder(parent: nil, name: "  ") }
        await #expect(throws: VaultError.self) { try await service.moveFolder(uuid: acme, parent: billing) }

        let made = try await service.createFolder(parent: personal, name: " Taxes ")
        #expect(made.name == "Taxes")
        #expect(made.parent == personal)
        try await service.renameFolder(uuid: made.id, name: "Tax 2026")
        try await service.moveFolder(uuid: made.id, parent: nil)
        #expect(try await service.folders().first { $0.uuid == made.id }?.parent == nil)

        let rows = try await service.items(archived: .all)
        let inBilling = rows.filter { $0.folder == billing }.count
        #expect(try await service.deleteFolder(uuid: billing) == inBilling)
        let after = try await service.items(archived: .all)
        #expect(after.count == rows.count)
        #expect(after.filter { $0.folder == acme }.count == rows.filter { $0.folder == acme }.count + inBilling)
        await #expect(throws: VaultError.self) { try await service.setItemFolder(id: rows[0].id, folder: billing) }

        let item = rows[0].id
        try await service.setItemFolder(id: item, folder: personal)
        #expect(try await service.item(id: item).folderPath == ["Personal"])
        try await service.setItemFolder(id: item, folder: nil)
        #expect(try await service.item(id: item).folder == nil)
    }

    @Test func thePreviewOptionsMakeTheOwnerTheSource() async throws {
        let service = PreviewVaultService()
        let openAI = try await service.items(archived: .no).first { $0.title == "OpenAI" }!
        #expect(try await service.item(id: openAI.id).environment == nil)
        try await service.setItemOptions(id: openAI.id, alwaysAsk: true, environment: .production)
        let detail = try await service.item(id: openAI.id)
        #expect(detail.alwaysAsk == true)
        #expect(detail.environment == .production)
        #expect(detail.environmentSource == .owner)
        #expect(detail.row.production == true)
        try await service.setItemOptions(id: openAI.id, alwaysAsk: nil, environment: .staging)
        #expect(try await service.item(id: openAI.id).row.production == false)
        #expect(try await service.item(id: openAI.id).alwaysAsk == true)
    }

    @Test func aLockedPreviewRefuses() async throws {
        let service = PreviewVaultService(unlocked: false)
        do {
            _ = try await service.folders()
            Issue.record("a locked vault listed folders")
        } catch let error as VaultError {
            #expect(error.code == .locked)
        }
        await #expect(throws: VaultError.self) { try await service.detect(text: "synthetic") }
    }
}
