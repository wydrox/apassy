import Foundation

/// The duplicates of the preview vault, close enough to the core for the screens: logins with the
/// same website host and username, other items of one kind with the same secrets, and a conflict
/// copy with its original. A merge copies the fields that the kept item lacks and archives the
/// others. No value is real, and none leaves the actor.
extension PreviewVaultService {
    // MARK: Groups

    public func duplicates() async throws -> [DuplicateGroup] {
        try requireUnlocked()
        let active = items.filter { !$0.value.row.archived }
        var keyOf: [UInt64: String] = [:]
        for (id, item) in active {
            if let key = Self.duplicateKey(item) { keyOf[id] = key }
        }
        // A conflict copy of a sync belongs with its original.
        for (id, item) in active.sorted(by: { $0.key < $1.key }) {
            guard let original = item.row.conflictOf, active[original] != nil else { continue }
            let key = keyOf[original] ?? "copy|\(original)"
            keyOf[original] = key
            keyOf[id] = key
        }
        var byKey: [String: [UInt64]] = [:]
        for (id, key) in keyOf { byKey[key, default: []].append(id) }
        return byKey.values
            .filter { $0.count > 1 }
            .map { group($0.sorted()) }
            .sorted { lhs, rhs in
                let left = lhs.items.first?.title ?? "", right = rhs.items.first?.title ?? ""
                let order = left.localizedCaseInsensitiveCompare(right)
                return order == .orderedSame ? lhs.id.lexicographicallyPrecedes(rhs.id) : order == .orderedAscending
            }
    }

    private static func hasPasskey(_ item: Stored) -> Bool { item.passkey != nil || item.row.hasPasskey }

    /// What makes two items the same credential, or nil when the item has nothing to compare.
    private static func duplicateKey(_ item: Stored) -> String? {
        if item.row.kind == .login {
            let username = (item.fields.first { $0.role == .username }?.value ?? "").lowercased()
            guard !username.isEmpty, let host = item.row.websites.lazy.compactMap(Self.host).first else { return nil }
            return "login|\(host)|\(username)"
        }
        guard !item.secrets.isEmpty else { return nil }
        let secrets = item.secrets.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: "\u{1F}")
        return "\(item.row.kind.rawValue)|\(secrets)"
    }

    private static func host(_ site: String) -> String? {
        guard let host = URL(string: site.contains("://") ? site : "https://\(site)")?.host()?.lowercased(),
            !host.isEmpty
        else { return nil }
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }

    /// The value of a field for the comparison: the secret, or the plain value.
    private static func value(_ item: Stored, _ field: FieldView) -> String? {
        field.secret ? item.secrets[field.name] : field.value
    }

    private func group(_ ids: [UInt64]) -> DuplicateGroup {
        let members = ids.compactMap { items[$0] }
        let passkeys = members.filter(Self.hasPasskey)
        // The suggestion: the item with the passkey, else the latest change, else the oldest ID.
        let suggested =
            passkeys.first
            ?? members.max { lhs, rhs in
                let left = lhs.row.changedAt ?? 0, right = rhs.row.changedAt ?? 0
                return left == right ? lhs.row.id > rhs.row.id : left < right
            }
        var differences: [String] = []
        var seen: Set<String> = []
        for member in members {
            for field in member.fields where !seen.contains(field.name) {
                seen.insert(field.name)
                let values = members.map { other in
                    other.fields.first { $0.name == field.name }.flatMap { Self.value(other, $0) }
                }
                if Set(values.map { $0 ?? "\u{0}" }).count > 1 { differences.append(field.label) }
            }
        }
        if Set(members.map(\.notes)).count > 1 { differences.append("Notes") }
        if passkeys.count > 0, passkeys.count < members.count { differences.append("Passkey") }
        let mergeable = passkeys.count <= 1
        return DuplicateGroup(
            items: members.map {
                DuplicateMember(
                    id: $0.row.id, title: $0.row.title, kind: $0.row.kind, revision: $0.row.revision,
                    hasPasskey: Self.hasPasskey($0), changedAt: $0.row.changedAt ?? 0)
            },
            keep: suggested?.row.id ?? ids[0], differences: differences, identical: differences.isEmpty,
            mergeable: mergeable,
            reason: mergeable ? nil : "More than one of these items has a passkey. Each passkey stays in its own item.")
    }

    // MARK: Merge

    public func mergeDuplicates(keep: UInt64, keepRevision: UInt64, others: [DuplicateMergeOther]) async throws
        -> DuplicateMergeResult
    {
        var kept = try stored(keep)
        guard !others.isEmpty, !others.contains(where: { $0.id == keep }),
            Set(others.map(\.id)).count == others.count
        else { throw VaultError(.invalidInput, "Choose the item to keep and at least one other item.") }
        guard kept.row.revision == keepRevision, !kept.row.archived else {
            throw VaultError(.conflict, "These items changed. Check them again.")
        }
        var merged: [Stored] = []
        for other in others {
            let item = try stored(other.id)
            guard item.row.revision == other.revision, !item.row.archived else {
                throw VaultError(.conflict, "These items changed. Check them again.")
            }
            guard item.row.kind == kept.row.kind else {
                throw VaultError(.invalidInput, "Only items of one category can be merged.")
            }
            guard !Self.hasPasskey(item) else {
                throw VaultError(.invalidInput, "Keep the item with the passkey.")
            }
            merged.append(item)
        }
        let now = Int64(Date().timeIntervalSince1970)
        for item in merged {
            for field in item.fields where !kept.fields.contains(where: { $0.name == field.name }) {
                kept.fields.append(field)
                if field.secret, let secret = item.secrets[field.name] { kept.secrets[field.name] = secret }
            }
            if kept.notes.isEmpty { kept.notes = item.notes }
            for tag in item.row.tags where !kept.row.tags.contains(tag) { kept.row.tags.append(tag) }
            for site in item.row.websites where !kept.row.websites.contains(site) { kept.row.websites.append(site) }
            var archived = item
            archived.row.archived = true
            archived.row.revision += 1
            archived.row.changedAt = now
            items[item.row.id] = archived
        }
        kept.row.hasTotp = kept.fields.contains { $0.role == .totp }
        kept.row.hasPassword = Self.storesPassword(kept.secrets)
        kept.row.revision += 1
        kept.row.changedAt = now
        items[keep] = kept
        return DuplicateMergeResult(id: keep, revision: kept.row.revision, archived: others.map(\.id))
    }
}
