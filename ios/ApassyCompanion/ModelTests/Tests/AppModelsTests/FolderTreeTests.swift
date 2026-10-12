import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("FolderTree")
struct FolderTreeTests {
    private let acme = "acme"
    private let billing = "billing"
    private let personal = "personal"

    private func folder(_ uuid: String, _ parent: String?, _ name: String, _ position: Int64 = 0) -> Folder {
        Folder(uuid: uuid, parent: parent, name: name, position: position, count: 0)
    }

    /// Acme, Billing inside Acme, and Personal; depth first, as the core answers.
    private var tree: FolderTree {
        FolderTree([
            folder(acme, nil, "Acme"),
            folder(billing, acme, "Billing"),
            folder(personal, nil, "Personal", 1),
        ])
    }

    /// A chain A > B > C > D, four levels deep.
    private var chain: FolderTree {
        FolderTree([
            folder("a", nil, "A"),
            folder("b", "a", "B"),
            folder("c", "b", "C"),
            folder("d", "c", "D"),
        ])
    }

    private func row(_ id: UInt64, _ title: String, folder: String? = nil, archived: Bool = false) -> ItemRow {
        ItemRow(
            id: id, revision: 1, title: title, kind: .login, subtitle: "", websites: [], tags: [],
            archived: archived, hasTotp: false, conflictOf: nil, addedAt: nil, changedAt: nil, usedAt: nil,
            folder: folder)
    }

    @Test("pathLabel joins the names, and says no folder for nil and for an unknown folder")
    func pathLabel() {
        #expect(tree.pathLabel(nil) == FolderTree.noFolder)
        #expect(FolderTree.noFolder == "No folder")
        #expect(tree.pathLabel(billing) == "Acme › Billing")
        #expect(tree.pathLabel(acme) == "Acme")
        #expect(tree.pathLabel("unknown") == "No folder")
    }

    @Test("children lists the folders right under a parent")
    func children() {
        #expect(tree.children(of: nil).map(\.uuid) == [acme, personal])
        #expect(tree.children(of: acme).map(\.uuid) == [billing])
        #expect(tree.childNames(acme) == "Billing")
        #expect(tree.childNames(personal) == "")
    }

    @Test("subtree holds a folder and the folders below it, and level counts from 0")
    func subtreeAndLevel() {
        #expect(tree.subtree(acme) == [acme, billing])
        #expect(tree.subtree(billing) == [billing])
        #expect(tree.level(acme) == 0)
        #expect(tree.level(billing) == 1)
    }

    @Test("count adds the subfolders, skips archived items, and reads a gone folder as the top level")
    func count() {
        let items = [
            row(1, "In Acme", folder: acme),
            row(2, "In Billing", folder: billing),
            row(3, "Archived in Billing", folder: billing, archived: true),
            row(4, "In Personal", folder: personal),
            row(5, "Gone folder", folder: "gone"),
            row(6, "No folder"),
        ]
        #expect(tree.count(acme, in: items) == 2)
        #expect(tree.count(billing, in: items) == 1)
        #expect(tree.count(personal, in: items) == 1)
        #expect(tree.folder(of: items[4]) == nil)
        #expect(tree.folder(of: items[1]) == billing)
        #expect(tree.items(in: nil, of: items).map(\.id).sorted() == [5, 6])
    }

    @Test("items(in:of:) lists the direct, not archived items A–Z")
    func itemsInFolder() {
        let items = [
            row(1, "Zulu", folder: acme),
            row(2, "alpha", folder: acme),
            row(3, "Mid", folder: acme),
            row(4, "Archived", folder: acme, archived: true),
            row(5, "In Billing", folder: billing),
        ]
        #expect(tree.items(in: acme, of: items).map(\.title) == ["alpha", "Mid", "Zulu"])
        #expect(tree.items(in: billing, of: items).map(\.title) == ["In Billing"])
    }

    @Test("groups put the credentials without a folder first, then folders by path, A–Z")
    func groups() {
        let items = [
            row(1, "Netflix", folder: personal),
            row(2, "Stripe", folder: billing),
            row(3, "Zeta", folder: acme),
            row(4, "Beta", folder: acme),
            row(5, "Loose"),
        ]
        let groups = tree.groups(items)
        #expect(groups.map(\.title) == ["No folder", "Acme", "Acme › Billing", "Personal"])
        #expect(groups.map(\.folder) == [nil, acme, billing, personal])
        #expect(groups[1].items.map(\.title) == ["Beta", "Zeta"])
        #expect(groups[0].id == "")
    }

    @Test("a folder without credentials has no group")
    func emptyFoldersHaveNoGroup() {
        let groups = tree.groups([row(1, "Netflix", folder: personal)])
        #expect(groups.map(\.title) == ["Personal"])
        #expect(tree.groups([]).isEmpty)
    }

    @Test("choices go depth first with levels and drop excluded folders")
    func choices() {
        let all = tree.choices()
        #expect(all.map(\.folder.uuid) == [acme, billing, personal])
        #expect(all.map(\.level) == [0, 1, 0])
        #expect(tree.choices(excluding: [billing]).map(\.folder.uuid) == [acme, personal])
        #expect(tree.choices(excluding: [acme]).map(\.folder.uuid) == [personal])
    }

    @Test("moveTargets leaves out the folder and its subtree")
    func moveTargetsExcludeSubtree() {
        #expect(tree.moveTargets(for: acme).map(\.folder.uuid) == [personal])
        #expect(tree.moveTargets(for: billing).map(\.folder.uuid) == [acme, personal])
    }

    @Test("moveTargets keeps the folder and the levels below it within the maximum depth")
    func moveTargetsRespectDepth() {
        #expect(Folder.maxDepth == 4)
        // B has height 3 (B, C, D); the only folder outside its subtree is A at level 0: 0 + 1 + 3 <= 4.
        #expect(chain.moveTargets(for: "b").map(\.folder.uuid) == ["a"])
        // D has height 1: A (0 + 1 + 1), B (1 + 2), and C (2 + 2) all fit.
        #expect(chain.moveTargets(for: "d").map(\.folder.uuid) == ["a", "b", "c"])
        // A has height 4 and its subtree is everything: no folder is left.
        #expect(chain.moveTargets(for: "a").isEmpty)
    }

    @Test("canHoldSubfolder is false at the maximum depth and true at the top level")
    func canHoldSubfolder() {
        #expect(!chain.canHoldSubfolder("d"))
        #expect(chain.canHoldSubfolder("c"))
        #expect(chain.canHoldSubfolder(nil))
    }
}
