import ApassyVaultKit
import Foundation
import Observation

/// One item on the screen: its fields, and the secrets that the owner revealed after an owner
/// check. A revealed value stays for 30 s at most, and goes at once when the app leaves the
/// screen (`dropSecrets`).
@MainActor
@Observable
final class ItemDetailModel {
    /// A value in large type: one character per cell.
    struct LargeType: Identifiable, Equatable {
        let id = UUID()
        let label: String
        let value: String
        let secret: Bool
    }

    /// A one-time code on the screen, and when it arrived.
    struct ShownCode: Equatable {
        var code: TotpCode
        var fetchedAt: Date

        /// The seconds left of the code at `date`.
        func remaining(at date: Date) -> Double {
            max(0, Double(code.remaining) - date.timeIntervalSince(fetchedAt))
        }
    }

    let id: UInt64
    private(set) var detail: ItemDetail?
    private(set) var loadError: String?
    /// The item is not in the vault any more (deleted, here or on a Mac).
    private(set) var isGone = false
    /// Revealed secrets by field name.
    private(set) var revealed: [String: String] = [:]
    /// One-time codes on the screen by field name.
    private(set) var codes: [String: ShownCode] = [:]
    private(set) var largeType: LargeType?
    private(set) var history: [ItemEvent]?
    /// Fields whose owner check or call runs.
    private(set) var working: Set<String> = []

    @ObservationIgnored let vault: VaultModel
    @ObservationIgnored private let revealLifetime: Duration
    @ObservationIgnored private let now: @MainActor () -> Date
    @ObservationIgnored private var expiryTasks: [String: Task<Void, Never>] = [:]
    /// Bumped by `dropSecrets`. With `vault.revealEpoch` it marks a value that arrives after the
    /// screen dropped its secrets: such a value is not kept.
    @ObservationIgnored private var drops = 0

    init(
        id: UInt64, vault: VaultModel, revealLifetime: Duration = .seconds(30),
        now: @escaping @MainActor () -> Date = { Date() }
    ) {
        self.id = id
        self.vault = vault
        self.revealLifetime = revealLifetime
        self.now = now
    }

    var title: String { detail?.row.title ?? vault.item(id)?.title ?? "" }

    /// The item that this conflict copy was made from.
    var original: ItemRow? {
        guard let of = detail?.row.conflictOf else { return nil }
        return vault.item(of)
    }

    func load() async {
        do {
            let fresh = try await vault.service.item(id: id)
            // A changed item may have other fields: what was revealed belongs to the old version.
            if let detail, detail.row.revision != fresh.row.revision { dropSecrets() }
            detail = fresh
            loadError = nil
            isGone = false
            if history != nil { await loadHistory() }
        } catch let error as VaultError where error.code == .notFound {
            dropSecrets()
            isGone = true
        } catch let error as VaultError where error.code == .locked {
            vault.report(error)
        } catch {
            loadError = error.localizedDescription
        }
    }

    func loadHistory() async {
        history = (try? await vault.service.history(id: id)) ?? []
    }

    // MARK: Reveal

    func isRevealed(_ field: FieldView) -> Bool { revealed[field.name] != nil }

    /// Show a secret after the owner check, for 30 s.
    func reveal(_ field: FieldView) async {
        guard field.secret, !working.contains(field.name) else { return }
        working.insert(field.name)
        defer { working.remove(field.name) }
        let reason = "Show the \(VaultText.phrase(field.label)) of “\(title)”"
        let asked = stamp
        guard let value = await vault.releaseSecret(itemID: id, field: field.name, reason: reason), asked == stamp
        else { return }
        revealed[field.name] = value
        expire(field.name) { model in model.revealed[field.name] = nil }
    }

    func hide(_ field: FieldView) {
        revealed[field.name] = nil
        expiryTasks[field.name]?.cancel()
        expiryTasks[field.name] = nil
    }

    func copy(_ field: FieldView) async {
        guard !working.contains(field.name) else { return }
        working.insert(field.name)
        defer { working.remove(field.name) }
        await vault.copy(field, of: title, itemID: id)
    }

    // MARK: One-time codes

    /// Show the code after the owner check, for 30 s, as a revealed value. `runCode` fetches the
    /// next one each period while it shows.
    func showCode(_ field: FieldView) async {
        guard field.role == .totp, !working.contains(field.name) else { return }
        working.insert(field.name)
        defer { working.remove(field.name) }
        let asked = stamp
        guard await vault.gate.confirm(reason: "Show the one-time password of “\(title)”") else { return }
        await fetchCode(field.name, asked: asked)
        guard codes[field.name] != nil else { return }
        expire(Self.codeKey(field.name)) { model in model.codes[field.name] = nil }
    }

    func hideCode(_ field: FieldView) {
        codes[field.name] = nil
        expiryTasks[Self.codeKey(field.name)]?.cancel()
        expiryTasks[Self.codeKey(field.name)] = nil
    }

    /// While the code is on the screen, fetch the next one when the period ends. It stops when
    /// the code expires or the secrets are dropped; the view also cancels it when the item leaves
    /// the screen.
    func runCode(_ field: FieldView) async {
        let started = stamp
        while !Task.isCancelled, let shown = codes[field.name] {
            guard started == stamp else {
                codes[field.name] = nil
                return
            }
            // A little past the end of the period, checked at least each second.
            let wait = Double(shown.code.remaining) - now().timeIntervalSince(shown.fetchedAt) + 0.15
            if wait > 0 {
                try? await Task.sleep(for: .milliseconds(Int(min(wait, 1) * 1000)))
                continue
            }
            await fetchCode(field.name, asked: started)
        }
    }

    /// Fetch a code; it is kept only when nothing was dropped since `asked`.
    private func fetchCode(_ name: String, asked: Stamp) async {
        do {
            let code = try await vault.service.totp(id: id, field: name)
            guard asked == stamp else { return }
            codes[name] = ShownCode(code: code, fetchedAt: now())
        } catch {
            codes[name] = nil
            vault.report(error)
        }
    }

    private static func codeKey(_ name: String) -> String { "code:\(name)" }

    /// The drops of the vault and of this screen at a moment.
    private struct Stamp: Equatable {
        let epoch: Int
        let drops: Int
    }

    private var stamp: Stamp { Stamp(epoch: vault.revealEpoch, drops: drops) }

    /// Copy the current code, after its own owner check (a copy is its own action).
    func copyCode(_ field: FieldView) async {
        guard !working.contains(field.name) else { return }
        working.insert(field.name)
        defer { working.remove(field.name) }
        guard await vault.gate.confirm(reason: "Copy the one-time password of “\(title)”") else { return }
        do {
            let code = try await vault.service.totp(id: id, field: field.name)
            vault.copyGenerated(code.code)
        } catch {
            vault.report(error)
        }
    }

    // MARK: Large type

    /// Show a value in large type. A secret one after the owner check, for 30 s.
    func showLargeType(_ field: FieldView) async {
        guard !working.contains(field.name) else { return }
        if !field.secret {
            largeType = LargeType(label: field.label, value: field.value ?? "", secret: false)
            return
        }
        working.insert(field.name)
        defer { working.remove(field.name) }
        let reason = "Show the \(VaultText.phrase(field.label)) of “\(title)” in large type"
        let asked = stamp
        guard let value = await vault.releaseSecret(itemID: id, field: field.name, reason: reason), asked == stamp
        else { return }
        largeType = LargeType(label: field.label, value: value, secret: true)
        expire("largeType") { model in model.largeType = nil }
    }

    func closeLargeType() {
        largeType = nil
        expiryTasks["largeType"]?.cancel()
        expiryTasks["largeType"] = nil
    }

    // MARK: Dropping secrets

    /// Forget every revealed value and code: the app left the screen, or the vault locked.
    func dropSecrets() {
        drops += 1
        revealed = [:]
        codes = [:]
        if largeType?.secret == true { largeType = nil }
        for task in expiryTasks.values { task.cancel() }
        expiryTasks = [:]
    }

    private func expire(_ key: String, _ drop: @escaping @MainActor (ItemDetailModel) -> Void) {
        expiryTasks[key]?.cancel()
        let lifetime = revealLifetime
        expiryTasks[key] = Task { [weak self] in
            try? await Task.sleep(for: lifetime)
            guard !Task.isCancelled, let self else { return }
            drop(self)
            self.expiryTasks[key] = nil
        }
    }

    // MARK: Actions

    var isFavorite: Bool { vault.isFavorite(id) }

    func toggleFavorite() { vault.toggleFavorite(id) }

    func setArchived(_ archived: Bool) async {
        guard let row = detail?.row else { return }
        await vault.setArchived(row, archived)
        await load()
    }

    // MARK: The passkey

    /// What removing the passkey does to this item, with the revision on the screen. nil without
    /// a passkey.
    var passkeyRemovalPlan: PasskeyRemovalPlan? { detail.flatMap(PasskeyRemovalPlan.init(detail:)) }

    /// A login that signs in with its passkey only: removing the passkey deletes the item.
    var isPasskeyOnly: Bool { passkeyRemovalPlan?.deletesLogin == true }

    /// Remove the passkey after the owner check, as `plan` said it to the owner. The key is never
    /// read: the core drops it. True when the call succeeded; then `isGone` tells whether the
    /// whole login went.
    func removePasskey(_ plan: PasskeyRemovalPlan) async -> Bool {
        guard plan.itemID == id else { return false }
        let removed = await vault.removePasskey(plan)
        await load()
        return removed
    }

    /// Delete with the revision on the screen. True when it is gone.
    func delete() async -> Bool {
        guard let row = detail?.row else { return false }
        let deleted = await vault.delete(row)
        if !deleted { await load() }
        return deleted
    }
}
