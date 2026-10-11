// The state of one AutoFill request. The extension shows the choices, sends the call
// through the bridge, and opens Apassy. Apassy runs the owner check (Touch ID or the
// passphrase) itself, fresh for each fill, code, sign-in, or new passkey, and signs or
// reveals only after it. The extension has no LocalAuthentication check of its own:
// one check, in the app that holds the vault.
//
// The extension keeps no key, no seed, and no password. A password or a code goes to
// macOS at once. The list of identities for the system goes to ASCredentialIdentityStore
// (metadata only, IdentitySync.swift).

import AppKit
import AuthenticationServices
import Foundation
import os

let providerLog = Logger(subsystem: "com.wydrox.apassy.autofill", category: "provider")

enum ProviderOutcome {
    case password(ASPasswordCredential)
    case oneTimeCode(ASOneTimeCodeCredential)
    case passkeyAssertion(ASPasskeyAssertionCredential)
    case passkeyRegistration(ASPasskeyRegistrationCredential)
    case configured
    case cancelled
    case failed(ASExtensionError.Code)
}

/// A sign-in request of a website, from macOS (the system checked the origin).
struct AssertionRequest {
    let rpID: String
    let clientDataHash: Data
    let allowed: [Data]
}

/// A new passkey request of a website, from macOS.
struct RegistrationRequest {
    let rpID: String
    let userName: String
    let userHandle: Data
    let clientDataHash: Data
    let algorithms: [Int]
    let excluded: [Data]
    let needsLargeBlob: Bool
}

enum ChoiceKind {
    case password
    case passkey
    case oneTimeCode
}

struct PasskeyChoice: Identifiable, Hashable {
    let itemID: UInt64
    let credentialID: Data
    let title: String
    let userName: String
    var id: String { "\(itemID)/\(credentialID.base64EncodedString())" }
}

struct LoginChoice: Identifiable, Hashable {
    let id: UInt64
    let title: String
    let username: String
    let website: String
}

struct AttachChoice: Identifiable, Hashable {
    let id: UInt64
    let revision: UInt64
    let title: String
    let username: String
}

struct Choices {
    let kind: ChoiceKind
    let site: String
    let passkeys: [PasskeyChoice]
    let matches: [LoginChoice]
    let others: [LoginChoice]
}

struct RegistrationForm {
    let site: String
    let account: String
    let attachable: [AttachChoice]
}

enum Screen {
    case connecting
    /// Apassy is not running (`locked == false`) or its vault is locked.
    case waiting(locked: Bool)
    case choose(Choices)
    case register(RegistrationForm)
    /// The call waits for the owner check in Apassy.
    case confirm(String)
    case configured(String)
    case problem(String)
}

@MainActor
final class ProviderModel: ObservableObject {
    @Published private(set) var screen: Screen = .connecting
    @Published var showAllLogins = false
    @Published var newTitle = ""
    /// Nil: save the passkey as a new login.
    @Published var attachTarget: UInt64?

    private let finish: (ProviderOutcome) -> Void
    private let send: (Data) async throws -> Data
    private let identities: IdentityCoordinator
    private var work: Task<Void, Never>?
    private var done = false
    private var configuring = false
    private var assertion: AssertionRequest?
    private var registration: RegistrationRequest?
    private var attachable: [AttachChoice] = []
    private var openedApassy = false

    init(
        finish: @escaping (ProviderOutcome) -> Void,
        send: @escaping (Data) async throws -> Data = { try await BridgeClient.send($0) },
        identities: IdentityCoordinator = .system
    ) {
        self.finish = finish
        self.send = send
        self.identities = identities
    }

    // MARK: - Requests of macOS

    func startList(domains: [String], kind: ChoiceKind) {
        run {
            self.refreshIdentitiesQuietly()
            let list = try await self.call(AutofillListCall(domains: domains), as: FillListAnswer.self)
            self.screen = .choose(self.choices(kind: kind, site: domains.first ?? "", passkeys: [], list: list))
        }
    }

    func startPasskeyList(domains: [String], request: AssertionRequest) {
        assertion = request
        run {
            self.refreshIdentitiesQuietly()
            let listed = try await self.call(
                PasskeyListCall(rpId: request.rpID, allowed: request.allowed.map { $0.base64EncodedString() }),
                as: PasskeyListAnswer.self)
            let passkeys = listed.passkeys.compactMap { entry -> PasskeyChoice? in
                guard let credential = usablePasskey(entry, rpID: request.rpID, allowed: request.allowed) else { return nil }
                return PasskeyChoice(
                    itemID: entry.id, credentialID: credential, title: visibleText(entry.title, max: 80),
                    userName: visibleText(entry.userName.isEmpty ? entry.userDisplayName : entry.userName, max: 80))
            }
            // Logins of the same website, if the owner prefers the password.
            let logins = try? await self.call(AutofillListCall(domains: [request.rpID] + domains), as: FillListAnswer.self)
            let list = logins ?? FillListAnswer(matches: [], others: [])
            self.screen = .choose(Choices(
                kind: .passkey, site: request.rpID, passkeys: passkeys,
                matches: self.choices(kind: .password, site: request.rpID, passkeys: [], list: FillListAnswer(matches: list.matches, others: [])).matches,
                others: []))
        }
    }

    /// A password or a code that the owner picked in the system list (an identity).
    func startDirect(record: String?, user: String, domains: [String], kind: ChoiceKind) {
        run {
            guard let id = record.flatMap(UInt64.init) else { throw ProviderFailure.notFound }
            let list = try await self.call(AutofillListCall(domains: domains), as: FillListAnswer.self)
            guard let entry = (list.matches + list.others).first(where: { $0.id == id }),
                  kind == .oneTimeCode ? entry.hasTotp : entry.username == user
            else {
                throw ProviderFailure.notFound
            }
            try await self.fill(LoginChoice(id: id, title: entry.title, username: entry.username, website: entry.website ?? ""), kind: kind)
        }
    }

    /// A passkey that the owner picked in the system sheet (an identity).
    func startDirectPasskey(record: String?, credentialID: Data, userName: String, request: AssertionRequest) {
        assertion = request
        run {
            var itemID = record.flatMap(UInt64.init)
            var name = userName
            if itemID == nil {
                let listed = try await self.call(
                    PasskeyListCall(rpId: request.rpID, allowed: [credentialID.base64EncodedString()]), as: PasskeyListAnswer.self)
                let entry = listed.passkeys.first { usablePasskey($0, rpID: request.rpID, allowed: [credentialID]) != nil }
                itemID = entry?.id
                name = entry?.userName ?? userName
            }
            guard let itemID else { throw ProviderFailure.notFound }
            try await self.sign(PasskeyChoice(itemID: itemID, credentialID: credentialID, title: request.rpID, userName: visibleText(name, max: 80)))
        }
    }

    func startRegistration(_ request: RegistrationRequest) {
        registration = request
        // Apassy signs ES256 (-7) only, and stores no large blob.
        guard request.algorithms.contains(-7), !request.needsLargeBlob else {
            providerLog.info("registration refused: unsupported algorithm or extension")
            complete(.failed(.failed))
            return
        }
        run {
            let list = try await self.call(AutofillListCall(domains: [request.rpID]), as: FillListAnswer.self)
            self.attachable = list.matches.compactMap { entry in
                guard let revision = entry.revision, entry.hasPasskey != true else { return nil }
                return AttachChoice(id: entry.id, revision: revision, title: visibleText(entry.title, max: 80), username: visibleText(entry.username, max: 80))
            }
            self.newTitle = request.rpID
            self.attachTarget = nil
            self.screen = .register(RegistrationForm(
                site: request.rpID, account: visibleText(request.userName, max: 80), attachable: self.attachable))
        }
    }

    func startConfiguration() {
        configuring = true
        run {
            do {
                let count = try await IdentitySync.refresh({ body in try await self.exchange(body, confirm: nil) }, coordinator: self.identities)
                self.screen = .configured(count == 0
                    ? "Apassy AutoFill is on. Your vault has nothing to suggest yet."
                    : "Apassy AutoFill is on. Apassy suggests \(count) sign-ins.")
            } catch ProviderFailure.unsupported {
                // This Apassy app does not give the list of identities yet.
                self.screen = .configured("Apassy AutoFill is on. Choose Apassy in the passkey sheet of a website.")
            }
        }
    }

    // MARK: - Actions of the owner

    func choose(passkey: PasskeyChoice) {
        run { try await self.sign(passkey) }
    }

    func choose(login: LoginChoice, kind: ChoiceKind) {
        run { try await self.fill(login, kind: kind) }
    }

    func saveRegistration() {
        guard let request = registration else { return }
        let target = attachable.first { $0.id == attachTarget }
        let title = visibleText(newTitle, max: 128)
        run {
            let answer = try await self.call(
                PasskeyRegisterCall(
                    rpId: request.rpID, userName: request.userName, userDisplayName: request.userName,
                    userHandle: request.userHandle.base64EncodedString(),
                    clientDataHash: request.clientDataHash.base64EncodedString(), algorithms: request.algorithms,
                    excluded: request.excluded.map { $0.base64EncodedString() }, attachId: target?.id,
                    attachRevision: target?.revision, title: target == nil ? title : ""),
                as: PasskeyRegisterAnswer.self,
                confirm: "Save a passkey for \(visibleText(request.userName, max: 60)) on \(request.rpID).")
            let checked = try checkRegistration(answer, rpID: request.rpID)
            // Before macOS hears that the passkey exists: its next sign-in sheet reads the
            // system list, and that list was made before this passkey.
            await IdentitySync.publish(
                PasskeyEntry(
                    id: answer.id, title: title, rpId: request.rpID, userName: request.userName, userDisplayName: request.userName,
                    credentialId: answer.credentialId, userHandle: request.userHandle.base64EncodedString()),
                send: self.send, coordinator: self.identities)
            self.complete(.passkeyRegistration(ASPasskeyRegistrationCredential(
                relyingParty: request.rpID, clientDataHash: request.clientDataHash,
                credentialID: checked.credentialID, attestationObject: checked.attestationObject)))
        }
    }

    func cancel() {
        complete(configuring ? .configured : .cancelled)
    }

    func closeProblem() {
        complete(configuring ? .configured : .failed(.failed))
    }

    func doneConfiguring() {
        complete(.configured)
    }

    /// The sheet went away: end the call, so Apassy closes its owner check.
    func dismissed() {
        work?.cancel()
        complete(configuring ? .configured : .cancelled)
    }

    /// Open (or bring forward) the Apassy app that contains this extension.
    func openApassy() {
        let app = Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        guard app.pathExtension == "app" else { return }
        NSWorkspace.shared.open(app)
    }

    // MARK: - Calls

    private func sign(_ passkey: PasskeyChoice) async throws {
        guard let request = assertion else { throw ProviderFailure.failed("There is no sign-in request.") }
        let account = passkey.userName.isEmpty ? passkey.title : passkey.userName
        let answer = try await call(
            PasskeyAssertCall(
                id: passkey.itemID, rpId: request.rpID, credentialId: passkey.credentialID.base64EncodedString(),
                clientDataHash: request.clientDataHash.base64EncodedString()),
            as: PasskeyAssertAnswer.self,
            confirm: "Sign in to \(request.rpID) as \(account).")
        let checked = try checkAssertion(answer, rpID: request.rpID, credentialID: passkey.credentialID)
        complete(.passkeyAssertion(ASPasskeyAssertionCredential(
            userHandle: checked.userHandle, relyingParty: request.rpID, signature: checked.signature,
            clientDataHash: request.clientDataHash, authenticatorData: checked.authenticatorData,
            credentialID: checked.credentialID)))
    }

    private func fill(_ login: LoginChoice, kind: ChoiceKind) async throws {
        let name = login.title.isEmpty ? login.username : login.title
        if kind == .oneTimeCode {
            let answer = try await call(
                ItemCall(op: "autofill_code", id: login.id), as: OneTimeCodeAnswer.self,
                confirm: "Fill the one-time code of \(name).")
            complete(.oneTimeCode(ASOneTimeCodeCredential(code: try checkCode(answer))))
        } else {
            let answer = try await call(
                ItemCall(op: "autofill_credential", id: login.id), as: LoginSecretAnswer.self,
                confirm: "Fill the password of \(name).")
            complete(.password(ASPasswordCredential(user: answer.username, password: answer.password)))
        }
    }

    /// One call, decoded. See `exchange`.
    private func call<Answer: Decodable>(_ call: some Encodable, as type: Answer.Type, confirm: String? = nil) async throws -> Answer {
        try decodeAnswer(try await exchange(try encodeCall(call), confirm: confirm), as: type)
    }

    /// Send one call. While Apassy is not running or locked, open it once and try again
    /// every 2 seconds, up to 180 seconds. With `confirm`, show that the owner check runs
    /// in Apassy.
    private func exchange(_ body: Data, confirm: String?) async throws -> Data {
        let deadline = Date().addingTimeInterval(BridgeConstants.requestTimeout)
        while true {
            try Task.checkCancellation()
            if let confirm {
                screen = .confirm(confirm)
                openApassyOnce()
            }
            do {
                let data = try await callData(body)
                if let failure = answerFailure(data), failure == .notRunning || failure == .locked {
                    throw failure
                }
                return data
            } catch let failure as ProviderFailure where failure == .notRunning || failure == .locked {
                screen = .waiting(locked: failure == .locked)
                openApassyOnce()
                guard Date() < deadline else { throw ProviderFailure.timeout }
                try await Task.sleep(for: .seconds(2))
            }
        }
    }

    private func callData(_ body: Data) async throws -> Data {
        try await send(body)
    }

    private func openApassyOnce() {
        if !openedApassy {
            openedApassy = true
            openApassy()
        }
    }

    /// Update the system list of identities in the background. A failure changes nothing.
    private func refreshIdentitiesQuietly() {
        Task {
            _ = try? await IdentitySync.refresh({ body in try await self.send(body) }, coordinator: self.identities)
        }
    }

    private func choices(kind: ChoiceKind, site: String, passkeys: [PasskeyChoice], list: FillListAnswer) -> Choices {
        func usable(_ entry: FillEntry) -> LoginChoice? {
            guard kind != .oneTimeCode || entry.hasTotp else { return nil }
            return LoginChoice(
                id: entry.id, title: visibleText(entry.title, max: 80), username: visibleText(entry.username, max: 80),
                website: visibleText(entry.website ?? "", max: 80))
        }
        return Choices(
            kind: kind, site: site, passkeys: passkeys, matches: list.matches.compactMap(usable), others: list.others.compactMap(usable))
    }

    // MARK: - The end

    private func run(_ body: @escaping @MainActor () async throws -> Void) {
        work?.cancel()
        screen = .connecting
        work = Task {
            do {
                try await body()
            } catch {
                self.handle(error)
            }
        }
    }

    private func handle(_ error: Error) {
        guard !done else { return }
        if error is CancellationError {
            complete(configuring ? .configured : .cancelled)
            return
        }
        let failure = error as? ProviderFailure ?? .failed("Apassy sent an answer that AutoFill cannot use.")
        providerLog.info("request ended: \(String(describing: failure), privacy: .public)")
        switch failure {
        case .cancelled:
            complete(configuring ? .configured : .cancelled)
        case .excluded:
            complete(.failed(.matchedExcludedCredential))
        case .notFound:
            complete(.failed(.credentialIdentityNotFound))
        case .unsupported:
            complete(.failed(.failed))
        case .timeout:
            screen = .problem("Apassy did not answer in time. Open Apassy, unlock the vault, and try again.")
        case .bridgeRefused:
            screen = .problem("AutoFill could not verify the Apassy app. Install Apassy in the Applications folder and open it again.")
        case .notRunning, .locked:
            screen = .waiting(locked: failure == .locked)
        case .failed(let message):
            screen = .problem(message)
        }
    }

    private func complete(_ outcome: ProviderOutcome) {
        guard !done else { return }
        done = true
        work?.cancel()
        work = nil
        finish(outcome)
    }
}
