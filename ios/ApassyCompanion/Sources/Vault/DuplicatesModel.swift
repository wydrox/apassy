import ApassyVaultKit
import Foundation
import Observation

/// "Find duplicates": the groups of items that hold the same credential, as the core finds them
/// after an import or a sync conflict. A merge keeps one item of a group, with the fields that it
/// lacked, and moves the others to the archive, where the owner can bring them back. Each merge
/// starts with the owner check. The screen shows titles, kinds, times, and the labels of the fields
/// that differ, never a value.
@MainActor
@Observable
final class DuplicatesModel {
    enum Phase: Equatable {
        case loading
        case loaded
        case failed(String)
    }

    /// How a merge ended.
    private enum Outcome {
        case merged
        /// The core refused it; the message is in `alert`.
        case refused
        /// The core closed the vault: the lock screen shows.
        case closed
    }

    private(set) var phase: Phase = .loading
    private(set) var groups: [DuplicateGroup] = []
    /// An owner check or a merge runs.
    private(set) var isMerging = false
    /// The message of a failed merge. The screen shows it itself: the alert of the tabs cannot show
    /// above the Settings sheet.
    var alert: String?
    /// The owner's choice of the item to keep, by group. Without one, the suggestion of the core.
    private var choices: [DuplicateGroup.ID: UInt64] = [:]

    @ObservationIgnored let vault: VaultModel

    static let ownerReason = "Merge duplicates"
    static let changedMessage = "The items changed. Check the list again."
    static let mergeMessage = "The others move to the archive."
    static let mergeAllMessage = "Each group keeps one item. The others move to the archive."

    init(vault: VaultModel) {
        self.vault = vault
    }

    /// The groups that "Merge all identical" merges.
    var identicalGroups: [DuplicateGroup] { groups.filter { $0.identical && $0.mergeable } }

    /// Read the groups again. The list stays on the screen while it reloads.
    func load() async {
        if groups.isEmpty, phase != .loaded { phase = .loading }
        do {
            let fresh = try await vault.service.duplicates()
            groups = fresh
            choices = choices.filter { id, choice in
                fresh.first { $0.id == id }?.keepable.contains { $0.id == choice } == true
            }
            phase = .loaded
        } catch let error as VaultError where error.code == .locked {
            vault.report(error)
        } catch {
            groups = []
            phase = .failed(error.localizedDescription)
        }
    }

    // MARK: The item to keep

    /// The item that a merge keeps: the owner's choice, else the suggestion of the core. A member
    /// with a passkey is the only choice when there is one.
    func keepID(for group: DuplicateGroup) -> UInt64? {
        if let choice = choices[group.id], group.keepable.contains(where: { $0.id == choice }) { return choice }
        return group.suggestedKeep
    }

    func keptMember(of group: DuplicateGroup) -> DuplicateMember? {
        keepID(for: group).flatMap(group.member)
    }

    /// Choose the item to keep. A member that may not be kept is ignored.
    func choose(_ id: UInt64, for group: DuplicateGroup) {
        guard group.keepable.contains(where: { $0.id == id }) else { return }
        choices[group.id] = id
    }

    /// Whether the owner may choose another item to keep.
    func canChoose(in group: DuplicateGroup) -> Bool { group.mergeable && group.keepable.count > 1 }

    /// "Merge 2 items into “GitHub”?"
    func confirmationTitle(for group: DuplicateGroup) -> String {
        "Merge \(group.items.count) items into “\(keptMember(of: group)?.title ?? "")”?"
    }

    var mergeAllTitle: String {
        let count = identicalGroups.count
        return count == 1 ? "Merge 1 group of identical items?" : "Merge \(count) groups of identical items?"
    }

    // MARK: Merging

    /// Merge one group after the owner check, then read the groups again. The kept item, or nil when
    /// nothing was merged.
    @discardableResult
    func merge(_ group: DuplicateGroup) async -> DuplicateMember? {
        guard !isMerging, group.mergeable, let keep = keptMember(of: group) else { return nil }
        isMerging = true
        defer { isMerging = false }
        guard await vault.gate.confirm(reason: Self.ownerReason) else { return nil }
        let outcome = await mergeOne(group, keep: keep)
        if outcome != .closed { await load() }
        return outcome == .merged ? keep : nil
    }

    /// Merge every mergeable group whose values are the same, with one owner check, then read the
    /// groups again. Stops at the first refusal. The count of merged groups.
    @discardableResult
    func mergeAllIdentical() async -> Int {
        let targets = identicalGroups.compactMap { group in keptMember(of: group).map { (group, $0) } }
        guard !isMerging, !targets.isEmpty else { return 0 }
        isMerging = true
        defer { isMerging = false }
        guard await vault.gate.confirm(reason: Self.ownerReason) else { return 0 }
        var merged = 0
        var outcome = Outcome.merged
        for (group, keep) in targets {
            outcome = await mergeOne(group, keep: keep)
            guard outcome == .merged else { break }
            merged += 1
        }
        if outcome != .closed { await load() }
        return merged
    }

    private func mergeOne(_ group: DuplicateGroup, keep: DuplicateMember) async -> Outcome {
        do {
            _ = try await vault.mergeDuplicates(keep: keep, in: group)
            return .merged
        } catch let error as VaultError where error.code == .locked {
            vault.report(error)
            return .closed
        } catch let error as VaultError where error.code == .conflict {
            alert = Self.changedMessage
            await vault.reload()
            return .refused
        } catch {
            alert = error.localizedDescription
            await vault.reload()
            return .refused
        }
    }
}
