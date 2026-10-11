import ApassyVaultCore
import ApassyVaultKit
import AuthenticationServices
import Foundation
import Observation

/// What the extension hands back to iOS. A credential leaves this process only here.
enum AutoFillOutcome {
    case password(ASPasswordCredential)
    case oneTimeCode(ASOneTimeCodeCredential)
    case passkeyAssertion(ASPasskeyAssertionCredential)
    case passkeyRegistration(ASPasskeyRegistrationCredential)
    case cancelled
    /// The request cannot be done: a typed error of AuthenticationServices for iOS.
    case failed(ASExtensionError)
    case configured
}

/// A passkey sign-in that iOS asked for: the website, the hash to sign, and the passkeys it
/// accepts (all of the website when empty).
struct PasskeyAssertionContext {
    var rpID: String
    var clientDataHash: Data
    var allowed: [Data]
    var extensions: PasskeyExtensionRequest
}

/// A new passkey that a website asked for.
struct PasskeyRegistrationContext {
    var rpID: String
    var userName: String
    var userDisplayName: String
    var userHandle: Data
    var clientDataHash: Data
    var algorithms: [Int]
    var excluded: [Data]
    var extensions: PasskeyExtensionRequest
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
    enum Kind {
        /// A login, from the list; with `assertion`, the passkeys of the website too.
        case password
        case oneTimeCode
        /// A passkey that the owner picked in the passkey sheet of iOS.
        case passkey
        /// A new passkey for a website.
        case registration
    }

    enum Screen: Equatable {
        case loading
        /// A message and a Close button: no vault, or the vault did not open.
        case message(String)
        case unlock
        case list
        /// Where to save a new passkey.
        case register
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

    // Passkeys.
    /// The passkeys of the website that the request accepts.
    private(set) var passkeyMatches: [PasskeyCandidate] = []
    /// Why the passkeys of the website are not offered.
    private(set) var passkeyMessage: String?
    /// The new passkey: the website and the account.
    private(set) var registrationSummary: (rpID: String, userName: String)?
    /// Logins of the website without a passkey, which can take the new one.
    private(set) var attachCandidates: [ItemRow] = []
    /// The name of a new login for the passkey.
    var newPasskeyTitle = ""

    private let finish: @MainActor (AutoFillOutcome) -> Void
    private var service: (any VaultService)?
    private var vaultID: String?
    private var domains: [String] = []
    /// The record identifier of a QuickType suggestion.
    private var record: String?
    /// The username that the QuickType suggestion showed.
    private var recordUser: String?
    private var assertion: PasskeyAssertionContext?
    private var assertionAnswer = PasskeyExtensionRequest.Answer()
    private var registration: PasskeyRegistrationContext?
    private var registrationAnswer = PasskeyExtensionRequest.Answer()
    /// The passkey of a direct request.
    private var credentialID: Data?
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

    /// The passkey sheet of a website: its passkeys, then its logins. A request that fails a
    /// check offers the logins only.
    func startPasskeyList(for serviceIdentifiers: [ASCredentialServiceIdentifier], request: PasskeyAssertionContext) {
        kind = .password
        do {
            assertionAnswer = try PasskeyRequestCheck.assertion(
                rpID: request.rpID, credentialID: nil, clientDataHash: request.clientDataHash,
                extensions: request.extensions)
            assertion = request
        } catch {
            passkeyMessage = error.message
        }
        use(serviceIdentifiers.isEmpty ? [ASCredentialServiceIdentifier(identifier: request.rpID, type: .domain)] : serviceIdentifiers)
        Task { await open() }
    }

    /// A passkey that the owner picked in the sheet of iOS: sign with it after the owner check.
    func startPasskey(record: String?, credentialID: Data, request: PasskeyAssertionContext) {
        kind = .passkey
        self.record = record
        do {
            assertionAnswer = try PasskeyRequestCheck.assertion(
                rpID: request.rpID, credentialID: credentialID, clientDataHash: request.clientDataHash,
                extensions: request.extensions)
        } catch {
            fail(request: error)
            return
        }
        self.credentialID = credentialID
        assertion = PasskeyAssertionContext(
            rpID: request.rpID, clientDataHash: request.clientDataHash, allowed: [credentialID],
            extensions: request.extensions)
        host = request.rpID
        Task { await open() }
    }

    /// A website asks for a new passkey. A request that Apassy cannot answer fails at once,
    /// before the vault opens.
    func startRegistration(_ request: PasskeyRegistrationContext) {
        kind = .registration
        do {
            registrationAnswer = try PasskeyRequestCheck.registration(
                rpID: request.rpID, userHandle: request.userHandle, clientDataHash: request.clientDataHash,
                algorithms: request.algorithms, extensions: request.extensions)
        } catch {
            fail(request: error)
            return
        }
        registration = request
        registrationSummary = (request.rpID, request.userName.isEmpty ? request.userDisplayName : request.userName)
        newPasskeyTitle = request.rpID
        host = request.rpID
        Task { await open() }
    }

    /// The request fails a check: tell iOS why, with no vault opened.
    private func fail(request error: PasskeyRequestError) {
        guard !done else { return }
        done = true
        finish(.failed(ASExtensionError(.failed, userInfo: [ASExtensionLocalizedFailureReasonErrorKey: error.message])))
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
        let reason: String
        switch kind {
        case .password: reason = "Unlock “\(vaultName)” to fill a login."
        case .oneTimeCode: reason = "Unlock “\(vaultName)” to fill a one-time code."
        case .passkey: reason = "Unlock “\(vaultName)” to sign in with a passkey."
        case .registration: reason = "Unlock “\(vaultName)” to save a passkey."
        }
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

    /// After the owner check: fill the suggestion, sign, prepare a new passkey, or show the list.
    /// The unlock of this request is the owner check of the passkey: Face ID reads the
    /// passphrase with a new context, or the owner types it; nothing of an earlier request counts.
    private func unlocked() async {
        if await closeIfDone() { return }
        switch kind {
        case .passkey:
            await signDirect()
            return
        case .registration:
            await prepareRegistration()
            return
        case .password, .oneTimeCode: break
        }
        if let service, let vaultID, let id = CredentialIdentitySync.itemID(of: record, vaultID: vaultID) {
            do {
                // The suggestion names an item by its ID, which is local and may now be another
                // login: fill only when the item has the username that the suggestion showed.
                let item = try await service.item(id: id)
                if await closeIfDone() { return }
                // A one-time code suggestion shows the username, or the title of a login without one.
                let username = item.field(.username)?.value ?? ""
                if let user = recordUser,
                    username == user || (kind == .oneTimeCode && username.isEmpty && item.row.title == user)
                {
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
            if let assertion {
                passkeyMatches = try await service.passkeys(rpID: assertion.rpID, allowed: assertion.allowed)
            }
            if await closeIfDone() { return }
            switch kind {
            case .password:
                matches = list.matches
                others = list.others
            case .oneTimeCode:
                matches = list.matches.filter(\.hasTotp)
                others = list.others.filter(\.hasTotp)
            case .passkey, .registration:
                matches = []
                others = []
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

    // MARK: - Passkeys

    /// Sign with a passkey of the list.
    func choose(_ passkey: PasskeyCandidate) async {
        guard !busy, !done else { return }
        busy = true
        defer { busy = false }
        listMessage = nil
        do {
            try await sign(passkey)
        } catch {
            listMessage = Self.text(of: error)
        }
    }

    /// The passkey that the owner picked in the sheet of iOS. Its credential ID is the key: the
    /// record identifier only names the item that had it when the app published it.
    private func signDirect() async {
        guard let service, let assertion, let credentialID else { return }
        do {
            let found = try await service.passkeys(rpID: assertion.rpID, allowed: [credentialID])
            if await closeIfDone() { return }
            guard let passkey = found.first(where: { $0.credentialID == credentialID }) else {
                await close(.failed(ASExtensionError(.credentialIdentityNotFound)))
                return
            }
            try await sign(passkey)
        } catch {
            await fail(error)
        }
    }

    /// Sign the request's hash and hand the assertion to iOS. The vault is locked first.
    private func sign(_ passkey: PasskeyCandidate) async throws {
        guard let service, let assertion, !done else { return }
        let signed = try await service.passkeyAssert(
            PasskeyAssertionRequest(
                id: passkey.id, rpID: assertion.rpID, credentialID: passkey.credentialID,
                clientDataHash: assertion.clientDataHash))
        await close(
            .passkeyAssertion(
                ASPasskeyAssertionCredential(
                    userHandle: signed.userHandle, relyingParty: assertion.rpID, signature: signed.signature,
                    clientDataHash: assertion.clientDataHash, authenticatorData: signed.authenticatorData,
                    credentialID: signed.credentialID, extensionOutput: Self.output(assertionAnswer))))
    }

    /// Refuse a registration whose exclude list names a passkey of the vault, then offer where to
    /// save the new one.
    private func prepareRegistration() async {
        guard let service, let registration else { return }
        do {
            if !registration.excluded.isEmpty,
                !(try await service.passkeys(rpID: registration.rpID, allowed: registration.excluded)).isEmpty
            {
                await close(.failed(ASExtensionError(.matchedExcludedCredential)))
                return
            }
            let rows = try await service.items(archived: .no)
            if await closeIfDone() { return }
            attachCandidates = rows.filter {
                $0.kind == .login && !$0.hasPasskey && $0.conflictOf == nil
                    && $0.websites.contains { Self.belongs($0, to: registration.rpID) }
            }
            screen = .register
        } catch {
            await fail(error)
        }
    }

    /// Whether a website of a login is on the relying party or under it.
    static func belongs(_ website: String, to rpID: String) -> Bool {
        let text = website.contains("://") ? website : "https://\(website)"
        guard var host = URL(string: text)?.host()?.lowercased() else { return false }
        if host.hasSuffix(".") { host.removeLast() }
        let rp = rpID.lowercased()
        return host == rp || host.hasSuffix("." + rp)
    }

    /// Save the new passkey: in a new login, or in `login`.
    func register(into login: ItemRow? = nil) async {
        guard let service, let registration, let vaultID, !busy, !done else { return }
        busy = true
        defer { busy = false }
        listMessage = nil
        let title = newPasskeyTitle.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let created = try await service.passkeyRegister(
                PasskeyRegistration(
                    rpID: registration.rpID, userName: registration.userName,
                    userDisplayName: registration.userDisplayName, userHandle: registration.userHandle,
                    clientDataHash: registration.clientDataHash, algorithms: registration.algorithms,
                    excluded: registration.excluded,
                    attach: login.map { PasskeyRegistration.Attach(id: $0.id, revision: $0.revision) },
                    title: title.isEmpty ? registration.rpID : title))
            let identity = PasskeyIdentity(
                id: created.id, rpID: registration.rpID,
                userName: registration.userName.isEmpty ? registration.userDisplayName : registration.userName,
                credentialID: created.credentialID, userHandle: registration.userHandle)
            await Self.publish(identity, vaultID: vaultID)
            await close(
                .passkeyRegistration(
                    ASPasskeyRegistrationCredential(
                        relyingParty: registration.rpID, clientDataHash: registration.clientDataHash,
                        credentialID: created.credentialID, attestationObject: created.attestationObject,
                        extensionOutput: Self.output(registrationAnswer))))
        } catch let error as VaultError where error.code == .excluded {
            await close(.failed(ASExtensionError(.matchedExcludedCredential)))
        } catch let error as VaultError where error.code == .unsupportedAlgorithm {
            await close(.failed(ASExtensionError(.failed, userInfo: [ASExtensionLocalizedFailureReasonErrorKey: error.message])))
        } catch {
            listMessage = Self.text(of: error)
        }
    }

    /// Tell iOS about the new passkey at once; the app replaces the whole list at its next unlock.
    /// The identity store can be slow, so this waits 2 s at most.
    private static func publish(_ identity: PasskeyIdentity, vaultID: String) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await CredentialIdentitySync.add(identity, vaultID: vaultID) }
            group.addTask { try? await Task.sleep(for: .seconds(2)) }
            await group.next()
            group.cancelAll()
        }
    }

    /// The extension outputs: only "not supported" answers, or none.
    private static func output(_ answer: PasskeyExtensionRequest.Answer) -> ASPasskeyAssertionCredentialExtensionOutput? {
        if answer.largeBlobReadEmpty { return ASPasskeyAssertionCredentialExtensionOutput(largeBlob: .read(data: nil)) }
        if answer.largeBlobWriteFailed { return ASPasskeyAssertionCredentialExtensionOutput(largeBlob: .write(success: false)) }
        return nil
    }

    private static func output(_ answer: PasskeyExtensionRequest.Answer) -> ASPasskeyRegistrationCredentialExtensionOutput? {
        guard answer.largeBlobUnsupported || answer.prfUnsupported else { return nil }
        return ASPasskeyRegistrationCredentialExtensionOutput(
            largeBlob: answer.largeBlobUnsupported ? .unsupported : nil, prf: answer.prfUnsupported ? .unsupported : nil)
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
        case .passkey, .registration:
            throw VaultError(.invalidInput, "This request needs a passkey.")
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
