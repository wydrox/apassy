import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("VaultQuery")
struct VaultQueryTests {
    @Test("the letter of a title is its first letter without accents, or a hash")
    func letters() {
        #expect(VaultQuery.letter(of: "GitHub") == "G")
        #expect(VaultQuery.letter(of: "éclair") == "E")
        #expect(VaultQuery.letter(of: "  zed") == "Z")
        #expect(VaultQuery.letter(of: "1Password") == "#")
        #expect(VaultQuery.letter(of: "") == "#")
    }

    @Test("sections run from A to Z with the hash last, and titles are sorted inside")
    func sections() {
        let items = [
            makeRow(1, "1Password"),
            makeRow(2, "Zed"),
            makeRow(3, "avocado"),
            makeRow(4, "éclair"),
            makeRow(5, "Apple"),
            makeRow(6, "Banana"),
        ]
        let sections = VaultQuery.sections(items)
        #expect(sections.map(\.letter) == ["A", "B", "E", "Z", "#"])
        #expect(sections[0].items.map(\.title) == ["Apple", "avocado"])
        #expect(sections[4].items.map(\.title) == ["1Password"])
    }

    @Test("search matches the title, the subtitle, a tag, and a website")
    func searchFields() {
        let items = [
            makeRow(1, "GitHub", subtitle: "octocat", websites: ["https://github.com"], tags: ["work"]),
            makeRow(2, "Netflix", subtitle: "family@example.com", websites: ["netflix.com"], tags: ["home"]),
        ]
        #expect(VaultQuery.search(items, text: "netflix").active.map(\.id) == [2])
        #expect(VaultQuery.search(items, text: "octo").active.map(\.id) == [1])
        #expect(VaultQuery.search(items, text: "family@").active.map(\.id) == [2])
        #expect(VaultQuery.search(items, text: "work").active.map(\.id) == [1])
        #expect(VaultQuery.search(items, text: "github.com").active.map(\.id) == [1])
    }

    @Test("search ignores case and accents")
    func searchFolding() {
        let items = [makeRow(1, "Café Noir"), makeRow(2, "Cafe Blanc")]
        #expect(VaultQuery.search(items, text: "CAFE").active.map(\.id) == [2, 1])
        #expect(VaultQuery.search(items, text: "café blanc").active.map(\.id) == [2])
        #expect(VaultQuery.search(items, text: "NOIR").active.map(\.id) == [1])
    }

    @Test("search needs every word")
    func searchWords() {
        let items = [makeRow(1, "GitHub", subtitle: "octocat"), makeRow(2, "GitLab", subtitle: "tanuki")]
        #expect(VaultQuery.search(items, text: "git octo").active.map(\.id) == [1])
        #expect(VaultQuery.search(items, text: "git nothing").active.isEmpty)
        #expect(VaultQuery.search(items, text: "  git   tanuki ").active.map(\.id) == [2])
    }

    @Test("search puts archived items in their own list")
    func searchArchived() {
        let items = [makeRow(1, "Heroku", archived: true), makeRow(2, "Heroku staging")]
        let found = VaultQuery.search(items, text: "heroku")
        #expect(found.active.map(\.id) == [2])
        #expect(found.archived.map(\.id) == [1])
    }

    @Test("empty search text finds nothing")
    func searchEmpty() {
        let items = [makeRow(1, "GitHub")]
        let empty = VaultQuery.search(items, text: "")
        #expect(empty.active.isEmpty && empty.archived.isEmpty)
        let blank = VaultQuery.search(items, text: "  \n ")
        #expect(blank.active.isEmpty && blank.archived.isEmpty)
    }

    @Test("recent is the five newest items that are not archived")
    func recent() {
        var items = (1...7).map { makeRow(UInt64($0), "Item \($0)", changedAt: Int64($0)) }
        items.append(makeRow(50, "Archived", archived: true, changedAt: 100))
        #expect(VaultQuery.recent(items).map(\.id) == [7, 6, 5, 4, 3])
        #expect(VaultQuery.recent(items, limit: 2).map(\.id) == [7, 6])
    }

    @Test("favorites keep the order of the IDs and skip missing and archived items")
    func favorites() {
        let items = [makeRow(1, "One"), makeRow(2, "Two", archived: true), makeRow(3, "Three")]
        #expect(VaultQuery.favorites(items, ids: [3, 99, 2, 1]).map(\.id) == [3, 1])
        #expect(VaultQuery.favorites(items, ids: []).isEmpty)
    }

    @Test("tags are unique without regard to case, sorted, and leave out archived-only tags")
    func tags() {
        let items = [
            makeRow(1, "One", tags: ["Work", "home"]),
            makeRow(2, "Two", tags: ["work", "Zed"]),
            makeRow(3, "Three", tags: ["only-archived", "home"], archived: true),
        ]
        #expect(VaultQuery.tags(items) == ["home", "Work", "Zed"])
    }

    @Test("filter keeps the kind and the tag, and nil keeps all")
    func filter() {
        let items = [
            makeRow(1, "One", kind: .login, tags: ["Work"]),
            makeRow(2, "Two", kind: .apiKey, tags: ["work"]),
            makeRow(3, "Three", kind: .login, tags: ["home"]),
        ]
        #expect(VaultQuery.filter(items, kind: nil, tag: nil).map(\.id) == [1, 2, 3])
        #expect(VaultQuery.filter(items, kind: .login, tag: nil).map(\.id) == [1, 3])
        #expect(VaultQuery.filter(items, kind: nil, tag: "WORK").map(\.id) == [1, 2])
        #expect(VaultQuery.filter(items, kind: .login, tag: "work").map(\.id) == [1])
        #expect(VaultQuery.filter(items, kind: .database, tag: nil).isEmpty)
    }

    @Test("sorted by change puts the newest first, and by title uses the title order")
    func sorted() {
        let items = [
            makeRow(1, "Beta", changedAt: 10),
            makeRow(2, "Alpha", changedAt: 30),
            makeRow(3, "Gamma", changedAt: 20),
            makeRow(4, "Never"),
        ]
        #expect(VaultQuery.sorted(items, by: .changed).map(\.id) == [2, 3, 1, 4])
        #expect(VaultQuery.sorted(items, by: .title).map(\.id) == [2, 1, 3, 4])
    }

    @Test("a category lists its kind without archived items, and the archive lists the archived")
    func categories() {
        let items = [
            makeRow(1, "Login", kind: .login),
            makeRow(2, "Old login", kind: .login, archived: true),
            makeRow(3, "Key", kind: .apiKey),
        ]
        #expect(VaultQuery.items(items, in: .kind(.login)).map(\.id) == [1])
        #expect(VaultQuery.items(items, in: .archive).map(\.id) == [2])
        #expect(VaultQuery.items(items, in: .kind(.database)).isEmpty)
        #expect(VaultQuery.active(items).map(\.id) == [1, 3])
        #expect(VaultQuery.archived(items).map(\.id) == [2])
    }
}
