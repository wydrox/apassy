import ApassyVaultCore
import ApassyVaultKit
import AuthenticationServices
import Foundation
import Observation

/// What the extension hands back to iOS. A credential leaves this process only here.
enum AutoFillOutcome {
    case password(ASPasswordCredential)
    case oneTimeCode(ASOneTimeCodeCredential)
    case cancelled
    case configured
}

/// The vault of the extension: one per process, as `CoreVaultService` asks. iOS may
/// keep the process for the next request, so each request locks it when it ends.
@MainActor
enum VaultSource {
    private static var cached: (any VaultService)?

    static func service() throws -> any VaultService {
        if let cached { return cached }
        let service = try make()
        cached = service
        return service
    }

    private static func make() throws -> any VaultService {
        #if targetEnvironment(simulator)
        // Set by the app when it runs with -ApassyPreviewVault.
        if SharedContainer.defaults.bool(forKey: "ApassyPreviewVault") {
            return PreviewVaultService(empty: false, unlocked: false)
        }
        #endif
        // The app makes the folder when it adds a vault; the extension never writes.
        guard let directory = SharedContainer.dataDirectory(),
            FileManager.default.fileExists(atPath: directory.path(percentEncoded: false))
        else {
            throw VaultError(.noVault, "No vault is on this iPhone.")
        }
        return try CoreVaultService(dataDirectory: directory, deviceName: "iPhone", role: .autofill)
    }
}

/// One AutoFill request (ADR 0023): open the selected vault, check the owner once (Face
/// ID reads the stored passphrase, or the owner types it), fill one credential, lock.
@MainActor
@Observable
final class AutoFillModel {
    /// What iOS asked for.
    enum Kind { case password, oneTimeCode }

    enum Screen: Equatable {
        case loading
        /// A message and a Close button: no vault, or the vault did not open.
        case message(String)
        case unlock
        case list
        case configuration
    }

    private(set) var screen: Screen = .loading
    private(set) var kind: Kind = .password
    private(set) var vaultName = ""
    /// A step is running: the buttons wait.
    private(set) var busy = false

    // The owner check.
    private(set) var canUseBiometry = false
    private(set) var biometry: Biometry = .faceID
    /// The typed passphrase. Cleared after each attempt.
    var passphrase = ""
    private(set) var unlockMessage: String?

    // The list.
    /// The website of the request, for "Logins for <host>".
    private(set) var host: String?
    private(set) var matches: [FillCandidate] = []
    private(set) var others: [FillCandidate] = []
    private(set) var listMessage: String?
    var search = ""

    private let finish: @MainActor (AutoFillOutcome) -> Void
    private var service: (any VaultService)?
    private var vaultID: String?
    private var domains: [String] = []
    /// The record identifier of a QuickType suggestion.
    private var record: String?
    /// The username that the QuickType suggestion showed.
    private var recordUser: String?
    private var triedBiometry = false
    /// The request ended: no second fill, no second answer to iOS.
    private var done = false

    init(finish: @escaping @MainActor (AutoFillOutcome) -> Void) {
        self.finish = finish
    }

    // MARK: - Requests

    /// The list of logins (or of logins with a one-time password) for `serviceIdentifiers`.
    func startList(for serviceIdentifiers: [ASCredentialServiceIdentifier], kind: Kind) {
        self.kind = kind
        use(serviceIdentifiers)
        Task { await open() }
    }

    /// A QuickType suggestion: fill its item after the owner check, or show the list when
    /// the item is not in the vault or is not the login that the suggestion showed.
    func startDirect(record: String?, user: String?, serviceIdentifier: ASCredentialServiceIdentifier, kind: Kind) {
        self.kind = kind
        self.record = record
        recordUser = user
        use([serviceIdentifier])
        Task { await open() }
    }

    /// The owner turned Apassy on in Settings.
    func startConfiguration() {
        screen = .configuration
    }

    func configured() {
        guard !done else { return }
        done = true
        finish(.configured)
    }

    /// The owner closed the sheet. An unlock that still runs is closed when it returns
    /// (`closeIfDone`).
    func cancel() {
        Task { await close(.cancelled) }
    }

    /// The request ended while the core opened the vault: lock it again. True when it did.
    private func closeIfDone() async -> Bool {
        guard done else { return false }
        await lockVault()
        return true
    }

    /// The sheet went away without an answer of the extension (iOS ended the request).
    func dismissed() {
        guard !done else { return }
        done = true
        Task { await lockVault() }
    }

    // MARK: - Opening and the owner check

    private func use(_ serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let web = serviceIdentifiers.filter { $0.type == .domain || $0.type == .URL }
        domains = web.map(\.identifier)
        host = web.first.map(Self.host(of:))
    }

    private static func host(of identifier: ASCredentialServiceIdentifier) -> String {
        var host = identifier.identifier
        if identifier.type == .URL, let url = URL(string: host), let urlHost = url.host() {
            host = urlHost
        }
        host = host.lowercased()
        if host.hasPrefix("www.") { host.removeFirst(4) }
        return host
    }

    private func open() async {
        do {
            let service = try VaultSource.service()
            self.service = service
            let info = try await service.info()
            guard let vault = info.selectedVault ?? info.vaults.first else {
                screen = .message("Open Apassy to add your vault first.")
                return
            }
            if info.selected != vault.id {
                try await service.select(vaultID: vault.id)
            } else if info.unlocked {
                // Left open by an earlier request of this process: each fill needs its own check.
                try await service.lock()
            }
            vaultID = vault.id
            vaultName = vault.name
            let owner = BiometricOwnerCheck()
            biometry = owner.biometry
            canUseBiometry = biometry != .none && KeychainPassphraseStore().hasPassphrase(vaultID: vault.id)
            screen = .unlock
        } catch let error as VaultError where error.code == .noVault {
            screen = .message("Open Apassy to add your vault first.")
        } catch {
            screen = .message(Self.text(of: error))
        }
    }

    /// Face ID once, when the unlock screen shows.
    func autoUnlock() async {
        guard canUseBiometry, !triedBiometry else { return }
        await unlockWithBiometry()
    }

    func unlockWithBiometry() async {
        guard let service, let vaultID, !busy, !done else { return }
        triedBiometry = true
        busy = true
        defer { busy = false }
        unlockMessage = nil
        let reason =
            kind == .oneTimeCode
            ? "Unlock “\(vaultName)” to fill a one-time code." : "Unlock “\(vaultName)” to fill a login."
        let stored: String
        do {
            stored = try await KeychainPassphraseStore().read(vaultID: vaultID, reason: reason)
        } catch let error as VaultError {
            switch error.code {
            case .cancelled: break
            case .locked:
                // Face ID changed: the stored passphrase is gone.
                canUseBiometry = false
                unlockMessage = error.message
            default: unlockMessage = error.message
            }
            return
        } catch {
            unlockMessage = Self.text(of: error)
            return
        }
        guard !done else { return }
        do {
            try await service.unlock(passphrase: stored, keep: false)
            if await closeIfDone() { return }
        } catch let error as VaultError where error.code == .wrongPassphrase {
            canUseBiometry = false
            unlockMessage = "The saved passphrase does not open “\(vaultName)” any more."
            return
        } catch {
            unlockMessage = Self.text(of: error)
            return
        }
        await unlocked()
    }

    func unlockWithPassphrase() async {
        let typed = passphrase
        guard let service, !typed.isEmpty, !busy, !done else { return }
        busy = true
        defer { busy = false }
        unlockMessage = nil
        passphrase = ""
        do {
            try await service.unlock(passphrase: typed, keep: false)
            if await closeIfDone() { return }
        } catch {
            unlockMessage = Self.text(of: error)
            return
        }
        await unlocked()
    }

    /// After the owner check: fill the suggestion, or show the list.
    private func unlocked() async {
        if await closeIfDone() { return }
        if let service, let vaultID, let id = CredentialIdentitySync.itemID(of: record, vaultID: vaultID) {
            do {
                // The suggestion names an item by its ID, which is local and may now be another
                // login: fill only when the item has the username that the suggestion showed.
                let item = try await service.item(id: id)
                if await closeIfDone() { return }
                if let user = recordUser, item.field(.username)?.value == user {
                    try await fill(id)
                    return
                }
            } catch let error as VaultError where error.code == .notFound {
                // The suggestion is older than the vault: the owner picks from the list.
            } catch {
                await fail(error)
                return
            }
        }
        await loadList()
    }

    // MARK: - The list and the fill

    private func loadList() async {
        guard let service else { return }
        do {
            let list = try await service.autofillList(domains: domains)
            if await closeIfDone() { return }
            switch kind {
            case .password:
                matches = list.matches
                others = list.others
            case .oneTimeCode:
                matches = list.matches.filter(\.hasTotp)
                others = list.others.filter(\.hasTotp)
            }
            screen = .list
        } catch {
            await fail(error)
        }
    }

    /// The candidates that match the search.
    func filtered(_ candidates: [FillCandidate]) -> [FillCandidate] {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return candidates }
        return candidates.filter {
            $0.title.localizedStandardContains(query) || $0.username.localizedStandardContains(query)
                || ($0.website?.localizedStandardContains(query) ?? false)
        }
    }

    func choose(_ candidate: FillCandidate) async {
        guard !busy, !done else { return }
        busy = true
        defer { busy = false }
        listMessage = nil
        do {
            try await fill(candidate.id)
        } catch {
            listMessage = Self.text(of: error)
        }
    }

    /// Read one credential and hand it to iOS. The vault is locked before iOS gets it.
    private func fill(_ id: UInt64) async throws {
        guard let service, !done else { return }
        switch kind {
        case .password:
            let credential = try await service.autofillCredential(id: id)
            await close(.password(ASPasswordCredential(user: credential.username, password: credential.password)))
        case .oneTimeCode:
            let item = try await service.item(id: id)
            guard let field = item.field(.totp) else {
                throw VaultError(.notFound, "This login has no one-time password.")
            }
            let code = try await service.totp(id: id, field: field.name)
            await close(.oneTimeCode(ASOneTimeCodeCredential(code: code.code)))
        }
    }

    // MARK: - Ending

    private func close(_ outcome: AutoFillOutcome) async {
        guard !done else { return }
        done = true
        await lockVault()
        finish(outcome)
    }

    private func fail(_ error: any Error) async {
        await lockVault()
        screen = .message(Self.text(of: error))
    }

    private func lockVault() async {
        try? await service?.lock()
    }

    private static func text(of error: any Error) -> String {
        (error as? VaultError)?.message ?? "Apassy could not open the vault."
    }
}
