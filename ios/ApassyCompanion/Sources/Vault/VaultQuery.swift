import ApassyVaultKit
import Foundation

/// A group of items on Home: a kind, or the archive.
enum ItemCategory: Hashable, Identifiable, Sendable {
    case kind(ItemKind)
    case archive

    static let all: [ItemCategory] = ItemKind.allCases.map { .kind($0) } + [.archive]

    var id: String {
        switch self {
        case .kind(let kind): kind.rawValue
        case .archive: "archive"
        }
    }

    var label: String {
        switch self {
        case .kind(let kind): kind.pluralLabel
        case .archive: "Archive"
        }
    }

    var symbol: String {
        switch self {
        case .kind(let kind): kind.symbol
        case .archive: "archivebox"
        }
    }
}

/// The order of the item list.
enum ItemSort: String, CaseIterable, Identifiable, Sendable {
    case title
    case changed

    var id: String { rawValue }

    var label: String {
        switch self {
        case .title: "Title"
        case .changed: "Last changed"
        }
    }
}

/// The items under one letter of the A–Z list.
struct ItemSection: Identifiable, Equatable, Sendable {
    /// "A" to "Z", or "#" for a title that does not start with a letter.
    let letter: String
    let items: [ItemRow]

    var id: String { letter }
}

/// The lists that the screens show, made from the rows of the vault. No call to the core.
enum VaultQuery {
    static func active(_ items: [ItemRow]) -> [ItemRow] {
        items.filter { !$0.archived }
    }

    static func archived(_ items: [ItemRow]) -> [ItemRow] {
        items.filter(\.archived)
    }

    /// The items of a category on Home. A kind lists only items that are not archived.
    static func items(_ items: [ItemRow], in category: ItemCategory) -> [ItemRow] {
        switch category {
        case .kind(let kind): items.filter { !$0.archived && $0.kind == kind }
        case .archive: items.filter(\.archived)
        }
    }

    /// The newest changed items that are not archived, newest first.
    static func recent(_ items: [ItemRow], limit: Int = 5) -> [ItemRow] {
        Array(
            active(items)
                .sorted { ($0.changedAt ?? 0, $1.title) > ($1.changedAt ?? 0, $0.title) }
                .prefix(limit))
    }

    /// The favorites in the order of `ids`. An ID that is gone or archived is skipped.
    static func favorites(_ items: [ItemRow], ids: [UInt64]) -> [ItemRow] {
        let byID = Dictionary(items.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        return ids.compactMap { byID[$0] }.filter { !$0.archived }
    }

    /// Every tag of the items that are not archived, A–Z, each once without regard to case.
    static func tags(_ items: [ItemRow]) -> [String] {
        var seen = Set<String>()
        var tags: [String] = []
        for tag in active(items).flatMap(\.tags) where seen.insert(tag.lowercased()).inserted {
            tags.append(tag)
        }
        return tags.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    /// Items of one kind and with one tag; nil keeps all.
    static func filter(_ items: [ItemRow], kind: ItemKind?, tag: String?) -> [ItemRow] {
        items.filter { item in
            (kind == nil || item.kind == kind)
                && (tag == nil || item.tags.contains { $0.caseInsensitiveCompare(tag ?? "") == .orderedSame })
        }
    }

    static func sorted(_ items: [ItemRow], by sort: ItemSort) -> [ItemRow] {
        switch sort {
        case .title:
            items.sorted { titleOrder($0, $1) }
        case .changed:
            items.sorted { ($0.changedAt ?? 0) != ($1.changedAt ?? 0) ? ($0.changedAt ?? 0) > ($1.changedAt ?? 0) : titleOrder($0, $1) }
        }
    }

    private static func titleOrder(_ a: ItemRow, _ b: ItemRow) -> Bool {
        let order = a.title.localizedStandardCompare(b.title)
        return order == .orderedSame ? a.id < b.id : order == .orderedAscending
    }

    /// The A–Z sections of `items`, in title order, with "#" last.
    static func sections(_ items: [ItemRow]) -> [ItemSection] {
        let grouped = Dictionary(grouping: sorted(items, by: .title)) { letter(of: $0.title) }
        return grouped.keys
            .sorted { ($0 == "#" ? 1 : 0, $0) < ($1 == "#" ? 1 : 0, $1) }
            .map { ItemSection(letter: $0, items: grouped[$0] ?? []) }
    }

    /// The section letter of a title: its first letter without accents, A to Z, or "#".
    static func letter(of title: String) -> String {
        guard let first = title.trimmingCharacters(in: .whitespaces).first else { return "#" }
        let folded = String(first).folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil).uppercased()
        guard folded.count == 1, let scalar = folded.unicodeScalars.first, ("A"..."Z").contains(scalar) else {
            return "#"
        }
        return folded
    }

    /// The items whose title, subtitle, a tag, or a website contains every word of `text`,
    /// without regard to case or accents. Items that are not archived first, then the archived.
    static func search(_ items: [ItemRow], text: String) -> (active: [ItemRow], archived: [ItemRow]) {
        let words = text.split(whereSeparator: \.isWhitespace).map(String.init)
        guard !words.isEmpty else { return ([], []) }
        let found = sorted(items, by: .title).filter { item in
            let haystack = ([item.title, item.subtitle] + item.tags + item.websites).joined(separator: "\n")
            return words.allSatisfy { haystack.range(of: $0, options: [.caseInsensitive, .diacriticInsensitive]) != nil }
        }
        return (found.filter { !$0.archived }, found.filter(\.archived))
    }
}
