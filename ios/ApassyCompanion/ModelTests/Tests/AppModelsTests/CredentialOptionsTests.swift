import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("Credential looks and options")
struct CredentialOptionsTests {
    private let service = PreviewVaultService(empty: false, unlocked: true)

    private func row(
        kind: ItemKind = .login, subtitle: String = "", provider: String? = nil, production: Bool? = nil
    ) -> ItemRow {
        ItemRow(
            id: 1, revision: 1, title: "Title", kind: kind, subtitle: subtitle, websites: [], tags: [],
            archived: false, hasTotp: false, conflictOf: nil, addedAt: nil, changedAt: nil, usedAt: nil,
            provider: provider, production: production)
    }

    /// A detail from the preview vault with the environment set as the test says.
    private func detail(
        _ id: UInt64 = 100, environment: CredentialEnvironment?, source: DeclarationSource?
    ) async throws -> ItemDetail {
        var detail = try await service.item(id: id)
        detail.environment = environment
        detail.environmentSource = source
        return detail
    }

    // MARK: Looks

    @Test("a known provider gets a letter tile in its color")
    func tileOfProvider() {
        #expect(ProviderTileStyle.of(provider: "Stripe", title: "x", kind: .apiKey)
            == ProviderTileStyle(mark: .letter("S"), rgb: 0x635BFF))
        #expect(ProviderTileStyle.of(provider: nil, title: "Netflix", kind: .login)
            == ProviderTileStyle(mark: .letter("N"), rgb: 0xE50914))
    }

    @Test("without a provider, the service in the subtitle picks the tile, as the Mac's provider or service")
    func tileOfService() {
        let token = ItemRow(
            id: 1, revision: 1, title: "DNS token", kind: .apiKey, subtitle: "cloudflare", websites: [], tags: [],
            archived: false, hasTotp: false, conflictOf: nil, addedAt: nil, changedAt: nil, usedAt: nil)
        #expect(ProviderTileStyle.of(token) == ProviderTileStyle(mark: .letter("C"), rgb: 0xF48120))
        // The provider of the declaration comes first.
        #expect(ProviderTileStyle.of(row(kind: .apiKey, subtitle: "cloudflare", provider: "Stripe"))
            == ProviderTileStyle(mark: .letter("S"), rgb: 0x635BFF))
        #expect(ProviderTileStyle.of(row(kind: .custom, subtitle: "github"))
            == ProviderTileStyle(mark: .letter("G"), rgb: 0x1F2328))
        #expect(ProviderTileStyle.of(row(kind: .sshKey, subtitle: "sentry"))
            == ProviderTileStyle(mark: .letter("S"), rgb: 0x362D59))
        // A username, a host, and a public key name no service.
        #expect(ProviderTileStyle.of(row(kind: .login, subtitle: "stripe-admin")).mark == .kind(.login))
        #expect(ProviderTileStyle.of(row(kind: .database, subtitle: "github.example.com")).mark == .kind(.database))
        #expect(ProviderTileStyle.of(row(kind: .sshKey, subtitle: "ssh-ed25519 AAAAC3Nz github")).mark == .kind(.sshKey))
        #expect(ProviderTileStyle.of(row(kind: .apiKey)).mark == .kind(.apiKey))
    }

    @Test("PostgreSQL gets the database tile, and an unknown provider the tile of its kind")
    func tileOfDatabaseAndKind() {
        #expect(ProviderTileStyle.of(provider: "PostgreSQL", title: "x", kind: .database)
            == ProviderTileStyle(mark: .database, rgb: 0x336791))
        let unknown = ProviderTileStyle.of(provider: "Nobody", title: "Something", kind: .apiKey)
        #expect(unknown.mark == .kind(.apiKey))
        #expect(unknown.rgb == nil)
    }

    @Test("detailLine shows the username of a login and the kind of anything else")
    func detailLine() {
        #expect(CredentialLooks.detailLine(row(kind: .login, subtitle: "alice")) == "alice")
        #expect(CredentialLooks.detailLine(row(kind: .apiKey, subtitle: "stripe")) == "API key")
        #expect(CredentialLooks.detailLine(row(kind: .login)) == "Login")
    }

    @Test("headerLine joins the provider and the kind")
    func headerLine() {
        #expect(CredentialLooks.headerLine(row(kind: .apiKey, provider: "Stripe")) == "Stripe · API key")
        #expect(CredentialLooks.headerLine(row(kind: .apiKey)) == "API key")
    }

    @Test("the environment cap shows a confirmed environment and hides a default")
    func environmentCap() async throws {
        let production = try await detail(101, environment: .production, source: .signal)
        #expect(CredentialLooks.environmentCap(production) == CredentialLooks.Cap(label: "Production", red: true))
        let development = try await detail(100, environment: .development, source: .owner)
        #expect(CredentialLooks.environmentCap(development) == CredentialLooks.Cap(label: "Development", red: false))
        let unconfirmed = try await detail(103, environment: .production, source: .default)
        #expect(CredentialLooks.environmentCap(unconfirmed) == nil)
    }

    // MARK: Which change needs the owner

    @Test("turning Always ask off needs the owner, turning it on does not")
    func alwaysAskNeedsOwner() {
        #expect(CredentialOptions.alwaysAskNeedsOwner(from: true, to: false))
        #expect(!CredentialOptions.alwaysAskNeedsOwner(from: false, to: true))
        #expect(!CredentialOptions.alwaysAskNeedsOwner(from: true, to: true))
        #expect(!CredentialOptions.alwaysAskNeedsOwner(from: false, to: false))
    }

    @Test("every environment but production needs the owner, as on the Mac")
    func environmentNeedsOwner() async throws {
        let production = try await detail(environment: .production, source: .owner)
        #expect(CredentialOptions.environmentNeedsOwner(production, to: .development))
        #expect(!CredentialOptions.environmentNeedsOwner(production, to: .production))

        let development = try await detail(environment: .development, source: .owner)
        #expect(CredentialOptions.environmentNeedsOwner(development, to: .staging))
        #expect(CredentialOptions.environmentNeedsOwner(development, to: .local))

        let unconfirmed = try await detail(environment: .development, source: .default)
        #expect(CredentialOptions.environmentNeedsOwner(unconfirmed, to: .development))

        // Without a declaration every choice needs the check, production too, as on the Mac.
        let none = try await detail(environment: nil, source: nil)
        #expect(CredentialOptions.environmentNeedsOwner(none, to: .production))
        #expect(CredentialOptions.environmentNeedsOwner(none, to: .staging))
    }

    @Test("the Options group shows only when the core sends Always ask me")
    func optionsAvailable() async throws {
        #expect(CredentialOptions.isAvailable(try await service.item(id: 100)))
        var older = try await service.item(id: 100)
        older.alwaysAsk = nil
        older.environment = nil
        older.environmentSource = nil
        #expect(!CredentialOptions.isAvailable(older))
    }

    // MARK: VaultModel

    private func unlockedVault(check: ScriptedOwnerCheck = ScriptedOwnerCheck()) async -> VaultModel {
        let (vault, _) = makeVault(service: PreviewVaultService(empty: false, unlocked: true), check: check)
        await vault.start()
        vault.stopSync()
        return vault
    }

    @Test("start reads the folders of the vault")
    func startReadsFolders() async {
        let vault = await unlockedVault()
        #expect(vault.hasFolders)
        #expect(vault.folders.count == 3)
        #expect(vault.folderTree.pathLabel(PreviewOrganize.FolderID.billing) == "Acme › Billing")
    }

    @Test("a folder can be made and renamed")
    func createAndRenameFolder() async throws {
        let vault = await unlockedVault()
        let made = await vault.createFolder(parent: PreviewOrganize.FolderID.acme, name: "Payroll")
        let folder = try #require(made)
        #expect(folder.name == "Payroll")
        #expect(vault.folders.contains { $0.uuid == folder.uuid && $0.parent == PreviewOrganize.FolderID.acme })
        #expect(vault.folders.count == 4)

        #expect(await vault.renameFolder(folder, to: "Salaries"))
        #expect(vault.folders.first { $0.uuid == folder.uuid }?.name == "Salaries")
    }

    @Test("deleting a folder moves its credentials up and deletes none")
    func deleteFolder() async throws {
        let vault = await unlockedVault()
        let acme = try #require(vault.folders.first { $0.uuid == PreviewOrganize.FolderID.acme })
        let before = vault.items.count
        let inAcme = vault.items.filter { $0.folder == acme.uuid }.count
        #expect(inAcme > 0)

        let moved = await vault.deleteFolder(acme)
        #expect(moved == inAcme)
        #expect(vault.items.count == before)
        #expect(!vault.folders.contains { $0.uuid == acme.uuid })
        #expect(vault.folders.first { $0.uuid == PreviewOrganize.FolderID.billing }?.parent == nil)
        #expect(!vault.items.contains { $0.folder == acme.uuid })
    }

    @Test("moveItem puts a credential in a folder")
    func moveItem() async {
        let vault = await unlockedVault()
        #expect(vault.item(102)?.folder == nil)
        #expect(await vault.moveItem(102, to: PreviewOrganize.FolderID.personal))
        #expect(vault.item(102)?.folder == PreviewOrganize.FolderID.personal)
    }

    // MARK: ItemDetailModel

    private func detailModel(
        _ id: UInt64, check: ScriptedOwnerCheck = ScriptedOwnerCheck()
    ) async -> (ItemDetailModel, VaultModel) {
        let vault = await unlockedVault(check: check)
        let model = ItemDetailModel(id: id, vault: vault, revealLifetime: .milliseconds(80))
        await model.load()
        return (model, vault)
    }

    /// Runs `action`, which asks the owner: Face ID says no, so the passphrase prompt shows, and
    /// the owner closes it.
    private func refused(by vault: VaultModel, _ action: @escaping () async -> Void) async {
        let task = Task { await action() }
        #expect(await waitUntil { vault.gate.prompt != nil })
        vault.gate.cancel()
        await task.value
    }

    @Test("Always ask turns on at once and turns off only after the owner check")
    func setAlwaysAsk() async {
        let check = ScriptedOwnerCheck(answer: false)
        let (model, vault) = await detailModel(100, check: check)
        #expect(model.detail?.alwaysAsk == false)

        await model.setAlwaysAsk(true)
        #expect(model.detail?.alwaysAsk == true)
        #expect(check.calls == 0)

        await refused(by: vault) { await model.setAlwaysAsk(false) }
        #expect(model.detail?.alwaysAsk == true)
        #expect(check.calls == 1)

        check.answer = true
        await model.setAlwaysAsk(false)
        #expect(model.detail?.alwaysAsk == false)
        #expect(check.reasons.last == "Turn off “Always ask me” for “GitHub”")
        #expect(!model.isSavingOptions)
    }

    @Test("a less careful environment waits for the owner, production does not")
    func setEnvironment() async {
        let check = ScriptedOwnerCheck(answer: false)
        let (model, vault) = await detailModel(101, check: check)
        #expect(model.detail?.environment == .production)
        #expect(vault.item(101)?.production == true)

        await refused(by: vault) { await model.setEnvironment(.development) }
        #expect(model.detail?.environment == .production)
        #expect(check.calls == 1)

        check.answer = true
        await model.setEnvironment(.development)
        #expect(check.calls == 2)
        #expect(model.detail?.environment == .development)
        #expect(model.detail?.environmentSource == .owner)
        #expect(vault.item(101)?.production == false)

        await model.setEnvironment(.production)
        #expect(check.calls == 2)
        #expect(model.detail?.environment == .production)
        #expect(vault.item(101)?.production == true)
    }

    @Test("the folder label follows a move")
    func folderLabel() async {
        let (model, vault) = await detailModel(100)
        #expect(model.folderLabel == "Acme")
        #expect(await vault.moveItem(100, to: PreviewOrganize.FolderID.billing))
        await model.load()
        #expect(model.folderLabel == "Acme › Billing")
    }

    @Test("the first environment of a credential without a declaration waits for the owner, production too")
    func firstEnvironmentNeedsOwner() async {
        let check = ScriptedOwnerCheck(answer: false)
        let (model, vault) = await detailModel(102, check: check)
        #expect(model.detail?.environment == nil)

        await refused(by: vault) { await model.setEnvironment(.production) }
        #expect(model.detail?.environment == nil)
        #expect(check.calls == 1)

        check.answer = true
        await model.setEnvironment(.production)
        #expect(check.calls == 2)
        #expect(check.reasons.last == "Mark “OpenAI” as production")
        #expect(model.detail?.environment == .production)
        #expect(model.detail?.environmentSource == .owner)
    }
}
