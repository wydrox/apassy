import Foundation
import Testing

@testable import ApassyVaultKit

/// The duplicates models (`duplicates`, `duplicates_merge`) and the preview vault's groups and
/// merges. Synthetic values only.
@Suite struct DuplicatesTests {
    private struct Groups: Decodable { var groups: [DuplicateGroup] }

    /// The code of the error that a call throws, or nil when it does not throw.
    private func failure(_ body: () async throws -> Void) async -> VaultError.Code? {
        do {
            try await body()
            return nil
        } catch let error as VaultError {
            return error.code
        } catch {
            return nil
        }
    }

    // MARK: Models

    @Test func theGroupsDecode() throws {
        let json = """
            {"groups": [
              {"items": [
                 {"id": 12, "title": "Example", "kind": "login", "revision": 3, "has_passkey": false, "changed_at": 1791100000},
                 {"id": 40, "title": "Example (imported)", "kind": "login", "revision": 1, "has_passkey": true, "changed_at": 1791200000}],
               "keep": 40, "differences": ["Password", "Notes"], "identical": false, "mergeable": true, "reason": null},
              {"items": [
                 {"id": 7, "title": "Key A", "kind": "api_key", "revision": 2, "has_passkey": false, "changed_at": 1},
                 {"id": 8, "title": "Key B", "kind": "api_key", "revision": 5, "has_passkey": false, "changed_at": 2}],
               "keep": 8, "differences": [], "identical": true, "mergeable": false, "reason": "Synthetic reason."}]}
            """
        let groups = try JSONDecoder().decode(Groups.self, from: Data(json.utf8)).groups
        #expect(groups.count == 2)
        let first = groups[0]
        #expect(first.items.map(\.id) == [12, 40])
        #expect(first.items[1].hasPasskey)
        #expect(first.items[0].kind == .login)
        #expect(first.items[0].revision == 3)
        #expect(first.items[0].changedAt == 1_791_100_000)
        #expect(first.keep == 40)
        #expect(first.differenceSummary == "Differs: Password, Notes")
        #expect(first.reason == nil)
        #expect(first.id == [12, 40])
        let second = groups[1]
        #expect(second.items[0].kind == .apiKey)
        #expect(second.identical && !second.mergeable)
        #expect(second.reason == "Synthetic reason.")
        #expect(second.differenceSummary == "Same values")
    }

    @Test func theMergeResultDecodes() throws {
        let json = #"{"id": 40, "revision": 4, "archived": [12, 13]}"#
        let result = try JSONDecoder().decode(DuplicateMergeResult.self, from: Data(json.utf8))
        #expect(result == DuplicateMergeResult(id: 40, revision: 4, archived: [12, 13]))
    }

    @Test func aMemberWithAPasskeyIsTheOnlyChoice() {
        let group = DuplicateGroup(
            items: [
                DuplicateMember(id: 1, title: "A", kind: .login, revision: 1, hasPasskey: false, changedAt: 9),
                DuplicateMember(id: 2, title: "B", kind: .login, revision: 1, hasPasskey: true, changedAt: 1),
            ], keep: 1, differences: [], identical: true, mergeable: true, reason: nil)
        #expect(group.keepable.map(\.id) == [2])
        // The core's suggestion is not a member that may be kept: the passkey member is.
        #expect(group.suggestedKeep == 2)
        #expect(group.others(keeping: 2) == [DuplicateMergeOther(id: 1, revision: 1)])
    }

    @Test func theGroupIDDoesNotDependOnTheOrder() {
        let a = DuplicateMember(id: 5, title: "A", kind: .custom, revision: 1, hasPasskey: false, changedAt: 0)
        let b = DuplicateMember(id: 3, title: "B", kind: .custom, revision: 1, hasPasskey: false, changedAt: 0)
        let one = DuplicateGroup(items: [a, b], keep: 5, differences: [], identical: true, mergeable: true, reason: nil)
        let other = DuplicateGroup(items: [b, a], keep: 5, differences: [], identical: true, mergeable: true, reason: nil)
        #expect(one.id == other.id)
    }

    // MARK: The preview vault

    private func login(
        _ service: PreviewVaultService, title: String, username: String, website: String, password: String,
        notes: String = ""
    ) async throws -> SavedItem {
        try await service.save(
            id: nil, revision: nil,
            draft: ItemDraft(
                title: title, kind: .login, notes: notes, tags: [],
                fields: [
                    .named("username", username, secret: false),
                    .named("password", password, secret: true),
                    .detail("Website", website, secret: false),
                ]))
    }

    private func group(_ service: PreviewVaultService, containing id: UInt64) async throws -> DuplicateGroup? {
        try await service.duplicates().first { $0.items.contains { $0.id == id } }
    }

    @Test func loginsWithTheSameHostAndUsernameAreOneGroup() async throws {
        let service = PreviewVaultService()
        let first = try await login(
            service, title: "Example", username: "ada", website: "https://example.com/login", password: "synthetic-1")
        let second = try await login(
            service, title: "Example (imported)", username: "Ada", website: "www.example.com", password: "synthetic-2",
            notes: "synthetic note")
        let other = try await login(
            service, title: "Example other user", username: "bob", website: "https://example.com", password: "synthetic-1")
        let found = try #require(try await group(service, containing: first.id))
        #expect(Set(found.items.map(\.id)) == [first.id, second.id])
        #expect(!found.identical)
        #expect(found.differences.contains("Password"))
        #expect(found.differences.contains("Notes"))
        #expect(found.mergeable)
        #expect(try await group(service, containing: other.id) == nil)
    }

    @Test func otherItemsWithTheSameSecretsAreOneIdenticalGroup() async throws {
        let service = PreviewVaultService()
        let draft = ItemDraft(
            title: "Synthetic key", kind: .apiKey, notes: "", tags: [],
            fields: [.named("token", "synthetic-token-dup", secret: true)])
        let a = try await service.save(id: nil, revision: nil, draft: draft)
        let b = try await service.save(id: nil, revision: nil, draft: draft)
        let found = try #require(try await group(service, containing: a.id))
        #expect(Set(found.items.map(\.id)) == [a.id, b.id])
        #expect(found.identical)
        #expect(found.differences.isEmpty)
    }

    @Test func aConflictCopyIsGroupedWithItsOriginal() async throws {
        let service = PreviewVaultService()
        let groups = try await service.duplicates()
        let rows = try await service.items(archived: .no)
        let copy = try #require(rows.first { $0.conflictOf != nil })
        let found = try #require(groups.first { $0.items.contains { $0.id == copy.id } })
        #expect(found.items.contains { $0.id == copy.conflictOf })
    }

    @Test func noGroupHoldsAValue() async throws {
        let service = PreviewVaultService()
        _ = try await login(service, title: "A", username: "ada", website: "example.com", password: "synthetic-secret-x")
        _ = try await login(service, title: "B", username: "ada", website: "example.com", password: "synthetic-secret-y")
        let encoded = String(decoding: try JSONEncoder().encode(try await service.duplicates()), as: UTF8.self)
        #expect(!encoded.contains("synthetic-secret"))
    }

    @Test func aMergeKeepsOneItemWithTheMissingFieldsAndArchivesTheOthers() async throws {
        let service = PreviewVaultService()
        let kept = try await service.save(
            id: nil, revision: nil,
            draft: ItemDraft(
                title: "Example", kind: .login, notes: "", tags: ["one"],
                fields: [.named("username", "ada", secret: false), .detail("Website", "example.com", secret: false)]))
        let other = try await login(
            service, title: "Example (imported)", username: "ada", website: "example.com", password: "synthetic-pw",
            notes: "synthetic note")
        let found = try #require(try await group(service, containing: kept.id))
        let result = try await service.mergeDuplicates(
            keep: kept.id, keepRevision: kept.revision, others: found.others(keeping: kept.id))
        #expect(result.id == kept.id)
        #expect(result.revision == kept.revision + 1)
        #expect(result.archived == [other.id])
        let detail = try await service.item(id: kept.id)
        #expect(detail.row.title == "Example")
        #expect(detail.notes == "synthetic note")
        #expect(detail.row.hasPassword == true)
        #expect(try await service.reveal(id: kept.id, field: "password") == "synthetic-pw")
        #expect(try await service.item(id: other.id).row.archived)
        #expect(try await group(service, containing: kept.id) == nil)
        // The archive keeps the other item: it can come back.
        try await service.archive(id: other.id, archived: false)
        #expect(try await service.item(id: other.id).row.archived == false)
    }

    @Test func aStaleRevisionIsAConflict() async throws {
        let service = PreviewVaultService()
        let a = try await login(service, title: "A", username: "ada", website: "example.com", password: "synthetic-1")
        let b = try await login(service, title: "B", username: "ada", website: "example.com", password: "synthetic-2")
        let found = try #require(try await group(service, containing: a.id))
        // B changes after the owner saw the group.
        let detail = try await service.item(id: b.id)
        _ = try await service.save(
            id: b.id, revision: detail.row.revision,
            draft: ItemDraft(
                title: "B changed", kind: .login, notes: "", tags: [],
                fields: detail.fields.map { .named($0.name, $0.value, secret: $0.secret) }))
        let code = await failure {
            _ = try await service.mergeDuplicates(keep: a.id, keepRevision: a.revision, others: found.others(keeping: a.id))
        }
        #expect(code == .conflict)
        #expect(try await service.item(id: b.id).row.archived == false)
    }

    @Test func onlyTheItemWithThePasskeyMayBeKept() async throws {
        let service = PreviewVaultService()
        let passkey = try await service.passkeyRegister(
            PasskeyRegistration(
                rpID: "example.com", userName: "ada", userDisplayName: "Ada", userHandle: Data([1, 2]),
                clientDataHash: Data(repeating: 3, count: 32), algorithms: [-7], excluded: [], attach: nil,
                title: "Example"))
        let other = try await login(
            service, title: "Example (imported)", username: "ada", website: "https://example.com", password: "synthetic-pw")
        let found = try #require(try await group(service, containing: passkey.id))
        #expect(found.keep == passkey.id)
        #expect(found.keepable.map(\.id) == [passkey.id])
        let code = await failure {
            _ = try await service.mergeDuplicates(
                keep: other.id, keepRevision: other.revision, others: found.others(keeping: other.id))
        }
        #expect(code == .invalidInput)
        let merged = try await service.mergeDuplicates(
            keep: passkey.id, keepRevision: try await service.item(id: passkey.id).row.revision,
            others: found.others(keeping: passkey.id))
        #expect(merged.archived == [other.id])
        #expect(try await service.item(id: passkey.id).passkey != nil)
    }
}
