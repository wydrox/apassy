#if canImport(AuthenticationServices)
import AuthenticationServices
import CryptoKit
import Foundation

// Apple's credential exchange (iOS 26): another app hands its logins, one-time passwords, and
// passkeys to Apassy through the system, and Apassy hands its own to another app the same way.
// The data moves between the apps in memory; Apassy never writes it to a file.
//
// Import keeps logins (username and password), one-time passwords, and passkeys. Other kinds of
// the format (cards, Wi-Fi, documents, notes alone) count as `unsupported`. A passkey that fails
// a check counts as `invalid`, with no detail of which one, so the counts carry no account names.

/// Reading what another app exported.
@available(iOS 26.0, macOS 26.0, *)
public enum CredentialExchangeImport {
    /// One Apassy login to make.
    public struct Entry: Sendable, CustomStringConvertible {
        public var title: String
        public var notes: String
        public var tags: [String]
        public var website: String?
        public var username: String?
        public var password: String?
        /// An `otpauth://` URI.
        public var otp: String?
        public var passkey: PasskeyImportAccount?

        public var description: String { "CredentialExchangeImport.Entry([redacted])" }

        /// Something besides the passkey that the login keeps.
        var hasLoginData: Bool {
            password != nil || otp != nil || website != nil || !notes.isEmpty || !tags.isEmpty
        }
    }

    public struct Plan: Sendable {
        public var entries: [Entry]
        /// Items with nothing that Apassy keeps.
        public var unsupported: Int
        /// Passkeys that fail a check: not ES256, a damaged key, or an extension that Apassy cannot keep.
        public var invalid: Int
        /// The app that exported.
        public var exporter: String
    }

    /// The counts of an import, for the owner. No names, no values.
    public struct Report: Sendable, Equatable {
        /// New logins.
        public var imported = 0
        /// Passkeys among them.
        public var passkeys = 0
        /// Passkeys that the vault has already.
        public var existing = 0
        /// Entries the core refused.
        public var failed = 0
        public var unsupported = 0
        public var invalid = 0

        public init() {}

        /// One sentence for the owner.
        public var summary: String {
            var parts = ["Imported \(imported) \(imported == 1 ? "login" : "logins")"
                + (passkeys > 0 ? ", \(passkeys) with a passkey" : "") + "."]
            if existing > 0 { parts.append("\(existing) \(existing == 1 ? "passkey was" : "passkeys were") in the vault already.") }
            if invalid > 0 {
                parts.append("\(invalid) \(invalid == 1 ? "passkey" : "passkeys") could not be used: Apassy keeps ES256 passkeys without extension data.")
            }
            if failed > 0 { parts.append("\(failed) \(failed == 1 ? "item" : "items") could not be saved.") }
            if unsupported > 0 {
                parts.append("\(unsupported) \(unsupported == 1 ? "item has" : "items have") nothing that Apassy keeps (for example a card or a Wi-Fi network).")
            }
            return parts.joined(separator: " ")
        }
    }

    public static func plan(_ data: ASExportedCredentialData) -> Plan {
        var plan = Plan(entries: [], unsupported: 0, invalid: 0, exporter: data.exporterDisplayName)
        for account in data.accounts {
            for item in account.items {
                read(item, into: &plan)
            }
        }
        return plan
    }

    private static func read(_ item: ASImportableItem, into plan: inout Plan) {
        var passkeys: [ASImportableCredential.Passkey] = []
        var basic: ASImportableCredential.BasicAuthentication?
        var totp: ASImportableCredential.TOTP?
        var notes: [String] = []
        for credential in item.credentials {
            switch credential {
            case .passkey(let passkey): passkeys.append(passkey)
            case .basicAuthentication(let value) where basic == nil: basic = value
            case .totp(let value) where totp == nil: totp = value
            case .note(let note): notes.append(note.content.value)
            default: break
            }
        }
        let title = item.title.trimmingCharacters(in: .whitespacesAndNewlines)
        let website = item.scope?.urls.first.map(\.absoluteString)
        let username = basic?.userName?.value.nilIfEmpty
        let password = basic?.password?.value.nilIfEmpty
        let otp = totp.map {
            OTPAuthURI.make(
                secret: $0.secret, issuer: $0.issuer ?? title.nilIfEmpty, account: $0.userName ?? username,
                algorithm: $0.algorithm.rawValue, digits: Int($0.digits), period: Int($0.period))
        }
        var accepted: [PasskeyImportAccount] = []
        for passkey in passkeys {
            if let account = account(passkey, title: title) {
                accepted.append(account)
            } else {
                plan.invalid += 1
            }
        }
        let base = Entry(
            title: title.isEmpty ? (accepted.first?.rpID ?? website ?? "Imported login") : title,
            notes: notes.joined(separator: "\n\n"), tags: item.tags, website: website, username: username,
            password: password, otp: otp, passkey: nil)
        if accepted.isEmpty {
            // A login needs a password when it has no passkey.
            if password != nil {
                plan.entries.append(base)
            } else if passkeys.isEmpty {
                plan.unsupported += 1
            }
            return
        }
        // One passkey per login: the first takes the password and the code, the others stand alone.
        for (index, account) in accepted.enumerated() {
            var entry = base
            entry.passkey = account
            if index > 0 {
                entry = Entry(
                    title: base.title, notes: "", tags: base.tags, website: base.website,
                    username: account.userName.nilIfEmpty, password: nil, otp: nil, passkey: account)
            }
            plan.entries.append(entry)
        }
    }

    /// The passkey with its key normalized, or nil when it fails a check.
    static func account(_ passkey: ASImportableCredential.Passkey, title: String) -> PasskeyImportAccount? {
        if #available(iOS 26.4, macOS 26.4, *), let extensions = passkey.fido2Extensions {
            // PRF secrets and large blobs cannot be kept: importing without them would break what
            // the website stored with them. Refuse the passkey instead.
            if extensions.hmacCredentials != nil || extensions.largeBlob != nil { return nil }
        }
        guard PasskeyRequestCheck.importable(
            rpID: passkey.relyingPartyIdentifier, credentialID: passkey.credentialID, userHandle: passkey.userHandle),
            let key = try? PasskeyRequestCheck.normalizedKey(passkey.key)
        else { return nil }
        return PasskeyImportAccount(
            rpID: passkey.relyingPartyIdentifier, credentialID: passkey.credentialID, userHandle: passkey.userHandle,
            userName: passkey.userName, userDisplayName: passkey.userDisplayName, key: key,
            title: title.isEmpty ? passkey.relyingPartyIdentifier : title)
    }

    /// Save the plan in the vault. The caller checked the owner just before.
    public static func run(_ plan: Plan, service: any VaultService) async -> Report {
        var report = Report()
        report.unsupported = plan.unsupported
        report.invalid = plan.invalid
        for entry in plan.entries {
            if Task.isCancelled { break }
            do {
                if let passkey = entry.passkey {
                    try await importPasskey(entry, passkey, service: service, report: &report)
                } else {
                    _ = try await service.save(id: nil, revision: nil, draft: draft(entry, keeping: nil))
                    report.imported += 1
                }
            } catch {
                report.failed += 1
            }
        }
        return report
    }

    private static func importPasskey(
        _ entry: Entry, _ passkey: PasskeyImportAccount, service: any VaultService, report: inout Report
    ) async throws {
        let result = try await service.passkeyImport([passkey])
        if result.skippedExisting > 0 {
            report.existing += 1
            return
        }
        guard result.imported > 0 else {
            report.failed += 1
            return
        }
        report.imported += 1
        report.passkeys += 1
        guard entry.hasLoginData else { return }
        // The new login has the passkey only: add the password, the code, and the website.
        guard let id = try await service.passkeys(rpID: passkey.rpID, allowed: [passkey.credentialID]).first?.id else {
            return
        }
        let detail = try await service.item(id: id)
        _ = try await service.save(id: id, revision: detail.row.revision, draft: draft(entry, keeping: detail))
    }

    /// The draft of a login. With `keeping`, the stored fields stay as they are (a secret as nil
    /// keeps its value) and the entry adds what the item does not have.
    static func draft(_ entry: Entry, keeping detail: ItemDetail?) -> ItemDraft {
        var fields: [DraftField] = []
        var names = Set<String>()
        var hasWebsite = false
        var hasOTP = false
        for field in detail?.fields ?? [] {
            names.insert(field.name)
            if field.role == .website { hasWebsite = true }
            if field.role == .totp { hasOTP = true }
            if field.custom {
                fields.append(
                    field.secret
                        ? DraftField(name: field.name, label: field.label, value: nil, secret: true)
                        : .detail(field.label, field.value ?? "", secret: false))
            } else {
                fields.append(.named(field.name, field.secret ? nil : field.value ?? "", secret: field.secret))
            }
        }
        let username = entry.username ?? entry.passkey?.userName.nilIfEmpty
        if !names.contains("username"), let username { fields.append(.named("username", username, secret: false)) }
        if !names.contains("password"), let password = entry.password {
            fields.append(.named("password", password, secret: true))
        }
        let website = entry.website ?? entry.passkey.map { "https://\($0.rpID)" }
        if !hasWebsite, let website { fields.append(.detail("Website", website, secret: false)) }
        if !hasOTP, let otp = entry.otp { fields.append(.detail("One-time password", otp, secret: true)) }
        let notes = [detail?.notes ?? "", entry.notes].filter { !$0.isEmpty }.joined(separator: "\n\n")
        var tags = detail?.row.tags ?? []
        for tag in entry.tags where !tags.contains(tag) { tags.append(tag) }
        return ItemDraft(
            title: detail?.row.title ?? entry.title, kind: .login, notes: notes, tags: Array(tags.prefix(32)),
            fields: fields)
    }
}

/// Writing what Apassy hands to another app.
@available(iOS 26.0, macOS 26.0, *)
public enum CredentialExchangeExport {
    /// The relying party of the exporter: the website of Apassy.
    public static let exporterRelyingParty = "apassy.wyderka.cc"
    public static let exporterName = "Apassy"

    public static func data(
        _ export: CredentialExport, vaultID: String, formatVersion: ASExportedCredentialData.FormatVersion = .v1,
        now: Date = Date()
    ) -> ASExportedCredentialData {
        let items = export.items.compactMap { item(of: $0, vaultID: vaultID, now: now) }
        let account = ASImportableAccount(
            id: stableID("account:\(vaultID)"), userName: "", email: "", fullName: nil, collections: [], items: items)
        return ASExportedCredentialData(
            accounts: [account], formatVersion: formatVersion, exporterRelyingPartyIdentifier: exporterRelyingParty,
            exporterDisplayName: exporterName, timestamp: now)
    }

    static func item(of item: ExportedItem, vaultID: String, now: Date) -> ASImportableItem? {
        var credentials: [ASImportableCredential] = []
        if item.username != nil || item.password != nil {
            credentials.append(
                .basicAuthentication(
                    .init(
                        userName: item.username.map { field(.string, $0) },
                        password: item.password.map { field(.concealedString, $0) })))
        }
        if let passkey = item.passkey {
            credentials.append(
                .passkey(
                    .init(
                        credentialID: passkey.credentialID, relyingPartyIdentifier: passkey.rpID,
                        userName: passkey.userName, userDisplayName: passkey.userDisplayName,
                        userHandle: passkey.userHandle, key: passkey.key)))
        }
        if let totp = item.totp, let algorithm = ASImportableCredential.TOTP.Algorithm(rawValue: totp.algorithm.lowercased()) {
            credentials.append(
                .totp(
                    .init(
                        secret: totp.secret, period: UInt16(clamping: totp.period), digits: UInt16(clamping: totp.digits),
                        userName: totp.user, algorithm: algorithm, issuer: totp.issuer)))
        }
        guard !credentials.isEmpty else { return nil }
        if !item.notes.isEmpty { credentials.append(.note(.init(content: field(.string, item.notes)))) }
        let urls = item.websites.compactMap(url(of:))
        let scope = urls.isEmpty ? nil : ASImportableCredentialScope(urls: urls)
        // The format needs both dates; the iOS 26.0 initializer has no optional ones.
        let created = item.createdAt.map { Date(timeIntervalSince1970: TimeInterval($0)) } ?? now
        let changed = item.changedAt.map { Date(timeIntervalSince1970: TimeInterval($0)) } ?? created
        return ASImportableItem(
            id: stableID("item:\(vaultID):\(item.id)"), created: created, lastModified: changed, title: item.title,
            subtitle: item.username, favorite: false, scope: scope, credentials: credentials, tags: item.tags)
    }

    private static func field(_ type: ASImportableEditableField.FieldType, _ value: String) -> ASImportableEditableField {
        ASImportableEditableField(id: nil, fieldType: type, value: value)
    }

    static func url(of website: String) -> URL? {
        let text = website.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        let url = URL(string: text.contains("://") ? text : "https://\(text)")
        return url?.host() == nil ? nil : url
    }

    /// An ID that is the same at each export of the item and says nothing about it.
    static func stableID(_ text: String) -> Data {
        Data(SHA256.hash(data: Data(text.utf8)).prefix(16))
    }
}
#endif
