// watchOS has AuthenticationServices but no credential exchange (ADR 0039).
#if canImport(AuthenticationServices) && !os(watchOS)
import AuthenticationServices
import CryptoKit
import Foundation

// Apple's credential exchange (iOS 26): another app hands its logins, one-time passwords, and
// passkeys to Apassy through the system, and Apassy hands its own to another app the same way.
// The data moves between the apps in memory; Apassy never writes it to a file.
//
// Import keeps every item that has a value: logins (username and password), one-time passwords,
// passkeys of any key type with their PRF secrets and large blob, and the items without login
// data. Those become items of the kinds that the vault has (no new kind): an API key, an SSH key,
// or Custom ("Other") for a card, a Wi-Fi network, a document, an address, a name, a note, a code,
// a generated password, or custom fields. Values go into fields, never into titles, notes, or
// tags. A passkey that fails a check counts as `invalid`, an item with nothing to keep as
// `unsupported`, with no detail of which one, so the counts carry no account names.
//
// The vault rules that the mapping keeps (contract ios-core-v1, section 5.3; `build_draft`): a
// title of at most 128 bytes, notes of at most 8 KB, at most 10 custom details with labels of at
// most 31 bytes that differ without regard to case, at most 32 tags of at most 64 bytes, and a
// Custom item with exactly one main secret field (a plain name, not a built-in one). A login
// needs a username and a password unless it has a passkey. What does not fit on an item goes
// into another Custom item with the same title.

/// Reading what another app exported.
@available(iOS 26.0, macOS 26.0, *)
public enum CredentialExchangeImport {
    static let maxDetails = 10
    static let maxLabelBytes = 31
    static let maxTitleBytes = 128
    static let maxNotesBytes = 8192
    static let maxTags = 32
    static let maxTagBytes = 64
    /// The names that a Custom item cannot use for its main field (the core's `is_builtin`).
    static let builtinNames: Set<String> = [
        "service", "project", "token", "password", "private_key", "passphrase", "username", "host", "database",
        "public_key",
    ]
    /// Labels of a custom field that stay visible; any other text is hidden, as in the Mac
    /// 1Password importer (docs/operations/import-1password.md, section 3).
    static let plainLabels: Set<String> = [
        "username", "hostname", "host", "server", "port", "database", "database_type", "sid", "alias", "url",
        "website", "type", "filename", "name", "admin_console_url", "admin_console_username",
        "support_contact_url", "support_contact_phone", "region", "project", "service", "environment",
    ]

    /// A value that an item keeps besides its login: a custom detail (`label` is its label), or
    /// the main field of an item that is not a login (`label` is the field name).
    public struct Value: Sendable, Equatable, CustomStringConvertible {
        public var label: String
        public var value: String
        public var secret: Bool

        public init(_ label: String, _ value: String, secret: Bool) {
            self.label = label
            self.value = value
            self.secret = secret
        }

        public var description: String { "CredentialExchangeImport.Value([redacted])" }
    }

    /// One Apassy item to make: a login, or an item of another kind with a main field.
    public struct Entry: Sendable, CustomStringConvertible {
        public var kind: ItemKind
        public var title: String
        public var notes: String
        public var tags: [String]
        public var website: String?
        public var username: String?
        public var password: String?
        /// An `otpauth://` URI.
        public var otp: String?
        public var passkey: PasskeyImportAccount?
        /// The main field of an item that is not a login: `token` (API key), `private_key` (SSH
        /// key), or the one secret field of a Custom item. Always secret.
        public var main: Value?
        /// Custom details, in order, with labels that fit and differ.
        public var details: [Value]

        public init(
            kind: ItemKind = .login, title: String, notes: String = "", tags: [String] = [], website: String? = nil,
            username: String? = nil, password: String? = nil, otp: String? = nil,
            passkey: PasskeyImportAccount? = nil, main: Value? = nil, details: [Value] = []
        ) {
            self.kind = kind
            self.title = title
            self.notes = notes
            self.tags = tags
            self.website = website
            self.username = username
            self.password = password
            self.otp = otp
            self.passkey = passkey
            self.main = main
            self.details = details
        }

        public var description: String { "CredentialExchangeImport.Entry([redacted])" }

        /// Something besides the passkey that the login keeps.
        var hasLoginData: Bool {
            password != nil || otp != nil || website != nil || !notes.isEmpty || !tags.isEmpty || !details.isEmpty
        }
    }

    public struct Plan: Sendable {
        public var entries: [Entry]
        /// Items with nothing that Apassy keeps.
        public var unsupported: Int
        /// Passkeys that fail a check: a damaged key, a key type that Apassy does not know, or
        /// damaged extension data.
        public var invalid: Int
        /// The app that exported.
        public var exporter: String
    }

    /// The counts of an import, for the owner. No names, no values.
    public struct Report: Sendable, Equatable {
        /// New items.
        public var imported = 0
        /// Passkeys saved: in new logins, or on logins that the vault had (`attached`).
        public var passkeys = 0
        /// Passkeys that went on a login of the vault without a passkey.
        public var attached = 0
        /// Passkeys that the vault has already.
        public var existing = 0
        /// Entries the core refused.
        public var failed = 0
        public var unsupported = 0
        public var invalid = 0

        public init() {}

        /// A few sentences for the owner.
        public var summary: String {
            var first = "Imported \(imported) \(imported == 1 ? "item" : "items")"
            if passkeys > 0 { first += " and \(passkeys) \(passkeys == 1 ? "passkey" : "passkeys")" }
            var parts = [first + "."]
            if attached > 0 {
                parts.append(
                    "\(attached) \(attached == 1 ? "passkey went" : "passkeys went") on a login that was in the vault already.")
            }
            if existing > 0 { parts.append("\(existing) \(existing == 1 ? "passkey was" : "passkeys were") in the vault already.") }
            if invalid > 0 {
                parts.append(
                    "\(invalid) \(invalid == 1 ? "passkey" : "passkeys") could not be used: the key or its extension data is damaged or of a kind that Apassy does not know.")
            }
            if failed > 0 { parts.append("\(failed) \(failed == 1 ? "item" : "items") could not be saved.") }
            if unsupported > 0 {
                parts.append("\(unsupported) \(unsupported == 1 ? "item has" : "items have") nothing that Apassy can keep.")
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

    /// The values of one credential of an item that is not a login, with what it makes when it
    /// is the first one: a kind, a type tag, and a title.
    struct Group {
        var kind: ItemKind = .custom
        /// The field of the kind's main value (`values[0]`): `token` or `private_key`.
        var mainName: String?
        var tag: String?
        var title: String
        var values: [Value]
    }

    private static func read(_ item: ASImportableItem, into plan: inout Plan) {
        var passkeys: [ASImportableCredential.Passkey] = []
        var basic: ASImportableCredential.BasicAuthentication?
        var totp: ASImportableCredential.TOTP?
        var notes: [String] = []
        var groups: [Group] = []
        /// Custom fields, a second login, more codes: details of the item.
        var extra: [Value] = []
        let title = clip(item.title.trimmingCharacters(in: .whitespacesAndNewlines), maxTitleBytes)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        for credential in item.credentials {
            switch credential {
            case .passkey(let passkey): passkeys.append(passkey)
            case .basicAuthentication(let value):
                if basic == nil {
                    basic = value
                } else {
                    add("Username", value.userName, secret: false, to: &extra)
                    add("Password", value.password, secret: true, to: &extra)
                }
            case .totp(let value):
                if totp == nil {
                    totp = value
                } else {
                    extra.append(Value("One-time password", otpURI(value, title: title, username: nil), secret: true))
                }
            case .note(let note):
                let text = note.content.value.trimmingCharacters(in: .whitespacesAndNewlines)
                if !text.isEmpty { notes.append(text) }
            case .creditCard(let card): append(cardGroup(card), to: &groups)
            case .wifi(let wifi): append(wifiGroup(wifi), to: &groups)
            case .identityDocument(let document): append(identityGroup(document), to: &groups)
            case .passport(let passport): append(passportGroup(passport), to: &groups)
            case .driversLicense(let license): append(licenseGroup(license), to: &groups)
            case .address(let address): append(addressGroup(address), to: &groups)
            case .personName(let name): append(nameGroup(name), to: &groups)
            case .apiKey(let key): append(apiKeyGroup(key), to: &groups)
            case .sshKey(let key): append(sshKeyGroup(key), to: &groups)
            case .generatedPassword(let generated):
                var values: [Value] = []
                add("Password", generated.password, secret: true, to: &values)
                append(Group(title: "Generated password", values: values), to: &groups)
            case .customFields(let fields): extra += customValues(fields)
            case .itemReference: break
            @unknown default: break
            }
        }
        let website = item.scope?.urls.first.map(\.absoluteString)
        let username = basic?.userName?.value.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        let password = basic?.password?.value.nilIfEmpty
        let otp = totp.map { otpURI($0, title: title, username: username) }
        var accepted: [PasskeyImportAccount] = []
        for passkey in passkeys {
            if let account = account(passkey, title: title) {
                accepted.append(account)
            } else {
                plan.invalid += 1
            }
        }
        let noteText = notes.joined(separator: "\n\n")
        var tags = itemTags(item.tags)
        for tag in groups.compactMap(\.tag) where !tags.contains(tag) { tags.append(tag) }
        tags = fitTags(tags, keeping: Array(Set(groups.compactMap(\.tag))))
        // The values that are not login data, in the order of the item.
        var pool = groups.flatMap(\.values) + extra
        var itemNotes = noteText
        if noteText.utf8.count > maxNotesBytes {
            // Too long for the notes: a hidden detail keeps it whole.
            pool.append(Value("Note", noteText, secret: true))
            itemNotes = ""
        }

        if !accepted.isEmpty || password != nil {
            let loginTitle = title.isEmpty ? (accepted.first?.rpID ?? website ?? "Imported login") : title
            guard !accepted.isEmpty || username != nil else {
                // A password without a username is not a login of the vault: a Custom item, as the
                // Mac importer makes it.
                var values = [Value("Password", password ?? "", secret: true)]
                if let website { values.append(Value("Website", website, secret: false)) }
                if let otp { values.append(Value("One-time password", otp, secret: true)) }
                plan.entries += customEntries(
                    title: clip(loginTitle, maxTitleBytes), notes: itemNotes, tags: tags, values: values + pool)
                return
            }
            var base = Entry(
                title: clip(loginTitle, maxTitleBytes), notes: itemNotes, tags: tags, website: website,
                username: username, password: password, otp: otp)
            // A login with a passkey has a website: its own, or the relying party.
            let hasWebsite = website != nil || !accepted.isEmpty
            var used = Set<String>()
            if hasWebsite { used.insert("website") }
            if otp != nil { used.insert("one-time password") }
            let (fitted, rest) = fit(pool, budget: maxDetails - used.count, used: used)
            base.details = fitted
            if accepted.isEmpty {
                plan.entries.append(base)
            }
            // One passkey per login: the first takes the password, the code, and the details;
            // the others stand alone.
            for (index, account) in accepted.enumerated() {
                var entry = base
                entry.passkey = account
                if index > 0 {
                    entry = Entry(
                        title: base.title, tags: base.tags, website: base.website,
                        username: account.userName.nilIfEmpty, passkey: account)
                }
                plan.entries.append(entry)
            }
            if !rest.isEmpty {
                plan.entries += customEntries(title: base.title, notes: "", tags: tags, values: rest)
            }
            return
        }

        // No login: the other values make the item.
        if groups.isEmpty, otp == nil, username == nil, extra.isEmpty {
            if !noteText.isEmpty {
                // A note alone: the text is the hidden field `note`, as the Mac importer makes it.
                plan.entries.append(
                    Entry(
                        kind: .custom, title: title.isEmpty ? "Note" : title,
                        tags: fitTags(itemTags(item.tags) + ["note"], keeping: ["note"]),
                        main: Value("note", noteText, secret: true)))
            } else if passkeys.isEmpty {
                plan.unsupported += 1
            }
            return
        }
        if !passkeys.isEmpty && groups.isEmpty && otp == nil && extra.isEmpty {
            // A username with a passkey that failed its check: the passkey counts as invalid.
            return
        }
        let primary = groups.first
        var main: Value?
        var kind = ItemKind.custom
        var values: [Value] = []
        if let primary, primary.kind != .custom, let name = primary.mainName, let key = primary.values.first {
            kind = primary.kind
            main = Value(name, key.value, secret: true)
            values = Array(primary.values.dropFirst())
        } else if let primary {
            values = primary.values
        }
        if let website { values.append(Value("Website", website, secret: false)) }
        values += groups.dropFirst().flatMap(\.values)
        if let otp { values.append(Value("One-time password", otp, secret: true)) }
        if let username { values.append(Value("Username", username, secret: false)) }
        values += extra
        if itemNotes.isEmpty && !noteText.isEmpty { values.append(Value("Note", noteText, secret: true)) }
        let itemTitle =
            title.isEmpty
            ? (primary?.title ?? (otp != nil ? "One-time password" : username != nil ? "Login" : "Imported item")) : title
        if let main {
            let (fitted, rest) = fit(values, budget: maxDetails, used: [])
            plan.entries.append(Entry(kind: kind, title: itemTitle, notes: itemNotes, tags: tags, main: main, details: fitted))
            if !rest.isEmpty { plan.entries += customEntries(title: itemTitle, notes: "", tags: tags, values: rest) }
        } else if values.isEmpty {
            plan.unsupported += 1
        } else {
            plan.entries += customEntries(title: itemTitle, notes: itemNotes, tags: tags, values: values)
        }
    }

    // MARK: The values of each credential type

    private static func append(_ group: Group, to groups: inout [Group]) {
        if !group.values.isEmpty { groups.append(group) }
    }

    /// Add a field that has a value. A visible value is trimmed, as the core keeps it; a secret
    /// keeps its spaces.
    private static func add(_ label: String, _ field: ASImportableEditableField?, secret: Bool, to values: inout [Value]) {
        guard let field else { return }
        add(label, field.value, secret: secret, to: &values)
    }

    private static func add(_ label: String, _ text: String, secret: Bool, to values: inout [Value]) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        values.append(Value(label, secret ? text : trimmed, secret: secret))
    }

    private static func cardGroup(_ card: ASImportableCredential.CreditCard) -> Group {
        var values: [Value] = []
        add("Card number", card.number, secret: true, to: &values)
        add("Security code", card.verificationNumber, secret: true, to: &values)
        add("PIN", card.pin, secret: true, to: &values)
        add("Cardholder", card.fullName, secret: true, to: &values)
        add("Expiry", card.expiryDate, secret: true, to: &values)
        add("Valid from", card.validFrom, secret: true, to: &values)
        add("Card type", card.cardType, secret: false, to: &values)
        return Group(tag: "card", title: "Card", values: values)
    }

    private static func wifiGroup(_ wifi: ASImportableCredential.WiFi) -> Group {
        var values: [Value] = []
        add("Network", wifi.ssid, secret: false, to: &values)
        add("Security", wifi.networkSecurityType, secret: false, to: &values)
        add("Password", wifi.passphrase, secret: true, to: &values)
        if let hidden = wifi.hidden {
            let text = hidden.value.trimmingCharacters(in: .whitespacesAndNewlines)
            switch text.lowercased() {
            case "true": add("Hidden network", "Yes", secret: false, to: &values)
            case "false": add("Hidden network", "No", secret: false, to: &values)
            default: add("Hidden network", text, secret: false, to: &values)
            }
        }
        return Group(tag: "wifi", title: "Wi-Fi network", values: values)
    }

    /// A document: its type and issuing country are visible, every other value is hidden. The
    /// type is added only when the document has a value.
    private static func documentGroup(_ type: String, _ values: [Value]) -> Group {
        guard !values.isEmpty else { return Group(tag: "identity", title: type, values: []) }
        return Group(tag: "identity", title: type, values: [Value("Document type", type, secret: false)] + values)
    }

    private static func identityGroup(_ document: ASImportableCredential.IdentityDocument) -> Group {
        var values: [Value] = []
        add("Issuing country", document.issuingCountry, secret: false, to: &values)
        add("Document number", document.documentNumber, secret: true, to: &values)
        add("ID number", document.identificationNumber, secret: true, to: &values)
        add("Nationality", document.nationality, secret: true, to: &values)
        add("Full name", document.fullName, secret: true, to: &values)
        add("Birth date", document.birthDate, secret: true, to: &values)
        add("Birth place", document.birthPlace, secret: true, to: &values)
        add("Sex", document.sex, secret: true, to: &values)
        add("Issue date", document.issueDate, secret: true, to: &values)
        add("Expiry date", document.expiryDate, secret: true, to: &values)
        add("Issuing authority", document.issuingAuthority, secret: true, to: &values)
        return documentGroup("ID document", values)
    }

    private static func passportGroup(_ passport: ASImportableCredential.Passport) -> Group {
        var values: [Value] = []
        add("Issuing country", passport.issuingCountry, secret: false, to: &values)
        add("Passport number", passport.passportNumber, secret: true, to: &values)
        add("Passport type", passport.passportType, secret: true, to: &values)
        add("National ID number", passport.nationalIdentificationNumber, secret: true, to: &values)
        add("Nationality", passport.nationality, secret: true, to: &values)
        add("Full name", passport.fullName, secret: true, to: &values)
        add("Birth date", passport.birthDate, secret: true, to: &values)
        add("Birth place", passport.birthPlace, secret: true, to: &values)
        add("Sex", passport.sex, secret: true, to: &values)
        add("Issue date", passport.issueDate, secret: true, to: &values)
        add("Expiry date", passport.expiryDate, secret: true, to: &values)
        add("Issuing authority", passport.issuingAuthority, secret: true, to: &values)
        return documentGroup("Passport", values)
    }

    private static func licenseGroup(_ license: ASImportableCredential.DriversLicense) -> Group {
        var values: [Value] = []
        add("Issuing country", license.country, secret: false, to: &values)
        add("License number", license.licenseNumber, secret: true, to: &values)
        add("Region", license.territory, secret: true, to: &values)
        add("License class", license.licenseClass, secret: true, to: &values)
        add("Full name", license.fullName, secret: true, to: &values)
        add("Birth date", license.birthDate, secret: true, to: &values)
        add("Issue date", license.issueDate, secret: true, to: &values)
        add("Expiry date", license.expiryDate, secret: true, to: &values)
        add("Issuing authority", license.issuingAuthority, secret: true, to: &values)
        return documentGroup("Driver's license", values)
    }

    private static func addressGroup(_ address: ASImportableCredential.Address) -> Group {
        var values: [Value] = []
        add("Street", address.streetAddress, secret: true, to: &values)
        add("Postal code", address.postalCode, secret: true, to: &values)
        add("City", address.city, secret: true, to: &values)
        add("Region", address.territory, secret: true, to: &values)
        add("Country", address.country, secret: true, to: &values)
        add("Phone", address.telephone, secret: true, to: &values)
        return Group(tag: "identity", title: "Address", values: values)
    }

    private static func nameGroup(_ name: ASImportableCredential.PersonName) -> Group {
        var values: [Value] = []
        add("Title", name.title, secret: true, to: &values)
        add("Given name", name.given, secret: true, to: &values)
        add("Informal given name", name.givenInformal, secret: true, to: &values)
        add("Second given name", name.given2, secret: true, to: &values)
        add("Surname prefix", name.surnamePrefix, secret: true, to: &values)
        add("Surname", name.surname, secret: true, to: &values)
        add("Second surname", name.surname2, secret: true, to: &values)
        add("Credentials", name.credentials, secret: true, to: &values)
        add("Generation", name.generation, secret: true, to: &values)
        return Group(tag: "identity", title: "Name", values: values)
    }

    /// An API key is of the kind API key when it has the key (the field `token`).
    private static func apiKeyGroup(_ key: ASImportableCredential.APIKey) -> Group {
        var values: [Value] = []
        add("API key", key.key, secret: true, to: &values)
        let hasKey = !values.isEmpty
        add("Username", key.userName, secret: false, to: &values)
        add("URL", key.url, secret: false, to: &values)
        add("Key type", key.keyType, secret: false, to: &values)
        add("Valid from", key.validFrom, secret: false, to: &values)
        add("Expiry date", key.expiryDate, secret: false, to: &values)
        return Group(
            kind: hasKey ? .apiKey : .custom, mainName: hasKey ? "token" : nil, title: "API key", values: values)
    }

    /// An SSH key is of the kind SSH key: the vault takes any private key text, and the PEM of
    /// the PKCS #8 key of the format ("BEGIN PRIVATE KEY") is a form that OpenSSH reads.
    private static func sshKeyGroup(_ key: ASImportableCredential.SSHKey) -> Group {
        var values: [Value] = []
        let hasKey = !key.privateKey.isEmpty
        if hasKey { values.append(Value("Private key", pem(key.privateKey), secret: true)) }
        add("Key type", key.keyType, secret: false, to: &values)
        if let comment = key.keyComment { add("Comment", comment, secret: false, to: &values) }
        add("Created", key.creationDate, secret: false, to: &values)
        add("Expiry date", key.expiryDate, secret: false, to: &values)
        add("Key source", key.keyGenerationSource, secret: false, to: &values)
        return Group(
            kind: hasKey ? .sshKey : .custom, mainName: hasKey ? "private_key" : nil, title: "SSH key", values: values)
    }

    /// PKCS #8 DER as PEM.
    static func pem(_ der: Data) -> String {
        "-----BEGIN PRIVATE KEY-----\n"
            + der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
            + "\n-----END PRIVATE KEY-----\n"
    }

    /// Custom fields: hidden unless a field that is not concealed has a known plain label.
    static func customValues(_ fields: ASImportableCredential.CustomFields) -> [Value] {
        var values: [Value] = []
        for field in fields.fields {
            let label = (field.label ?? fields.label ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let secret = field.fieldType == .concealedString || !isPlainLabel(label)
            add(label.isEmpty ? "Field" : label, field.value, secret: secret, to: &values)
        }
        return values
    }

    static func isPlainLabel(_ label: String) -> Bool {
        let lower = label.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return plainLabels.contains(lower) || plainLabels.contains(lower.replacingOccurrences(of: " ", with: "_"))
    }

    private static func otpURI(_ totp: ASImportableCredential.TOTP, title: String, username: String?) -> String {
        OTPAuthURI.make(
            secret: totp.secret, issuer: totp.issuer ?? title.nilIfEmpty, account: totp.userName ?? username,
            algorithm: totp.algorithm.rawValue, digits: Int(totp.digits), period: Int(totp.period))
    }

    // MARK: The rules of the vault

    /// Cut `text` to at most `limit` UTF-8 bytes, on a character boundary.
    static func clip(_ text: String, _ limit: Int) -> String {
        guard text.utf8.count > limit else { return text }
        var out = ""
        for character in text {
            if out.utf8.count + character.utf8.count > limit { break }
            out.append(character)
        }
        return out
    }

    /// A label that fits and that `used` (lowercased) does not have: " 2", " 3" after it.
    static func uniqueLabel(_ label: String, used: Set<String>) -> String {
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        let base = clip(trimmed.isEmpty ? "Detail" : trimmed, maxLabelBytes).trimmingCharacters(in: .whitespaces)
        if !used.contains(base.lowercased()) { return base }
        var number = 2
        while true {
            let suffix = " \(number)"
            let candidate = clip(base, maxLabelBytes - suffix.utf8.count).trimmingCharacters(in: .whitespaces) + suffix
            if !used.contains(candidate.lowercased()) { return candidate }
            number += 1
        }
    }

    /// The first `budget` values with labels that fit and differ from `used` and each other, and
    /// the values that do not fit.
    static func fit(_ values: [Value], budget: Int, used: Set<String>) -> (fit: [Value], rest: [Value]) {
        var used = used
        var fitted: [Value] = []
        var rest: [Value] = []
        for value in values {
            guard fitted.count < budget else {
                rest.append(value)
                continue
            }
            var detail = value
            detail.label = uniqueLabel(value.label, used: used)
            used.insert(detail.label.lowercased())
            fitted.append(detail)
        }
        return (fitted, rest)
    }

    /// The field name of the main value of a Custom item: a plain name from its label, never a
    /// built-in name (a password is `secret`, as in the Mac importer).
    static func mainName(_ label: String) -> String {
        switch label {
        case "One-time password": return "otp"
        case "Note": return "note"
        case "Username": return "account_name"
        default: break
        }
        var name = ""
        for scalar in label.lowercased().unicodeScalars {
            if (97...122).contains(scalar.value) || (48...57).contains(scalar.value) {
                name.unicodeScalars.append(scalar)
            } else if !name.isEmpty && !name.hasSuffix("_") {
                name.append("_")
            }
        }
        while name.hasSuffix("_") { name.removeLast() }
        name = String(name.prefix(64))
        if name.isEmpty || builtinNames.contains(name) || name.hasPrefix("x_") || name.hasPrefix("passkey_") {
            return "secret"
        }
        return name
    }

    /// Custom items for `values`: each takes its first secret value (else its first value) as
    /// its main field and at most 10 details; what is left makes the next one, with the same
    /// title and tags.
    static func customEntries(title: String, notes: String, tags: [String], values: [Value]) -> [Entry] {
        var rest = values
        var entries: [Entry] = []
        while !rest.isEmpty {
            let chosen = rest.remove(at: rest.firstIndex(where: \.secret) ?? 0)
            let (fitted, more) = fit(rest, budget: maxDetails, used: [])
            entries.append(
                Entry(
                    kind: .custom, title: title, notes: entries.isEmpty ? notes : "", tags: tags,
                    main: Value(mainName(chosen.label), chosen.value, secret: true), details: fitted))
            rest = more
        }
        return entries
    }

    /// The tags of the other app that the vault takes: trimmed, cut to 64 bytes, without
    /// empty ones and repeats.
    static func itemTags(_ tags: [String]) -> [String] {
        var out: [String] = []
        for tag in tags {
            let text = clip(tag.trimmingCharacters(in: .whitespacesAndNewlines), maxTagBytes)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if !text.isEmpty && !out.contains(text) { out.append(text) }
        }
        return out
    }

    /// At most 32 tags; the type tags in `keeping` stay.
    static func fitTags(_ tags: [String], keeping: [String]) -> [String] {
        var unique: [String] = []
        for tag in tags where !unique.contains(tag) { unique.append(tag) }
        guard unique.count > maxTags else { return unique }
        let kept = unique.filter { keeping.contains($0) }
        let others = unique.filter { !keeping.contains($0) }
        return Array(others.prefix(max(0, maxTags - kept.count))) + kept
    }

    // MARK: Passkeys

    /// The passkey with its key checked (a P-256 key normalized) and its extension data, or nil
    /// when it fails a check.
    static func account(_ passkey: ASImportableCredential.Passkey, title: String) -> PasskeyImportAccount? {
        guard PasskeyRequestCheck.importable(
            rpID: passkey.relyingPartyIdentifier, credentialID: passkey.credentialID, userHandle: passkey.userHandle),
            let key = try? PasskeyRequestCheck.importKey(passkey.key).key
        else { return nil }
        var account = PasskeyImportAccount(
            rpID: passkey.relyingPartyIdentifier, credentialID: passkey.credentialID, userHandle: passkey.userHandle,
            userName: passkey.userName, userDisplayName: passkey.userDisplayName, key: key,
            title: title.isEmpty ? passkey.relyingPartyIdentifier : title)
        // iOS 26.4 and later give the extension data; iOS 26.0 does not.
        if #available(iOS 26.4, macOS 26.4, *), let extensions = passkey.fido2Extensions {
            if let hmac = extensions.hmacCredentials {
                // The PRF secrets of the CTAP hmac-secret extension: HMAC-SHA-256 only.
                guard hmac.algorithm == .sha256, !hmac.credentialWithUV.isEmpty, !hmac.credentialWithoutUV.isEmpty
                else { return nil }
                account.prf = PasskeyPRFSecrets(withUV: hmac.credentialWithUV, withoutUV: hmac.credentialWithoutUV)
            }
            if let blob = extensions.largeBlob {
                guard !blob.data.isEmpty, blob.uncompressedSize >= 0 else { return nil }
                account.largeBlob = PasskeyLargeBlob(data: blob.data, uncompressedSize: blob.uncompressedSize)
            }
        }
        return account
    }

    /// The host of a website or a relying party, lowercased, without a final dot.
    static func host(_ text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let url = URL(string: trimmed.contains("://") ? trimmed : "https://\(trimmed)")
        guard var host = url?.host()?.lowercased(), !host.isEmpty else { return nil }
        while host.hasSuffix(".") { host.removeLast() }
        return host.isEmpty ? nil : host
    }

    private static func accountName(_ text: String?) -> String? {
        text?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().nilIfEmpty
    }

    /// The login of the vault that an imported passkey goes on: the one active login without a
    /// passkey whose website is on the host of the relying party (or of the item) and whose
    /// username is the account of the passkey (or of the item), without regard to case. nil
    /// when no login or more than one matches.
    static func attachTarget(for entry: Entry, passkey: PasskeyImportAccount, rows: [ItemRow]) -> ItemRow? {
        let names = Set([accountName(passkey.userName), accountName(entry.username)].compactMap { $0 })
        let hosts = Set([host(passkey.rpID), entry.website.flatMap { host($0) }].compactMap { $0 })
        guard !names.isEmpty, !hosts.isEmpty else { return nil }
        let matches = rows.filter { row in
            row.kind == .login && !row.hasPasskey && !row.archived && row.conflictOf == nil
                && accountName(row.subtitle).map { names.contains($0) } == true
                && row.websites.contains { website in host(website).map { hosts.contains($0) } == true }
        }
        return matches.count == 1 ? matches[0] : nil
    }

    // MARK: Saving

    /// Save the plan in the vault. The caller checked the owner just before.
    public static func run(_ plan: Plan, service: any VaultService) async -> Report {
        var report = Report()
        report.unsupported = plan.unsupported
        report.invalid = plan.invalid
        /// The active items, for the attach of a passkey; read again after a change.
        var rows: [ItemRow]?
        for entry in plan.entries {
            if Task.isCancelled { break }
            do {
                if let passkey = entry.passkey {
                    try await importPasskey(entry, passkey, service: service, rows: &rows, report: &report)
                } else {
                    let (body, rest) = draft(entry, keeping: nil)
                    _ = try await service.save(id: nil, revision: nil, draft: body)
                    rows = nil
                    report.imported += 1
                    await save(rest, title: entry.title, tags: entry.tags, service: service, report: &report)
                }
            } catch {
                report.failed += 1
            }
        }
        return report
    }

    /// Values that did not fit on an item: Custom items with its title.
    private static func save(
        _ values: [Value], title: String, tags: [String], service: any VaultService, report: inout Report
    ) async {
        for entry in customEntries(title: title, notes: "", tags: tags, values: values) {
            do {
                _ = try await service.save(id: nil, revision: nil, draft: draft(entry, keeping: nil).draft)
                report.imported += 1
            } catch {
                report.failed += 1
            }
        }
    }

    private static func importPasskey(
        _ entry: Entry, _ passkey: PasskeyImportAccount, service: any VaultService, rows: inout [ItemRow]?,
        report: inout Report
    ) async throws {
        if rows == nil { rows = try? await service.items(archived: .no) }
        var account = passkey
        account.attachID = attachTarget(for: entry, passkey: passkey, rows: rows ?? [])?.id
        var result = try await service.passkeyImport([account])
        if account.attachID != nil, result.imported == 0, result.skippedExisting == 0 {
            // The login changed since the list, or the core did not take it: a new login.
            account.attachID = nil
            result = try await service.passkeyImport([account])
        }
        rows = nil
        if result.skippedExisting > 0 {
            report.existing += 1
            return
        }
        guard result.imported > 0 else {
            report.failed += 1
            return
        }
        report.passkeys += 1
        if account.attachID != nil {
            report.attached += 1
        } else {
            report.imported += 1
        }
        guard entry.hasLoginData else { return }
        // The login has the passkey: add the password, the code, the website, and the details
        // that it does not have.
        let id: UInt64
        if let attachID = account.attachID {
            id = attachID
        } else {
            guard let found = try await service.passkeys(rpID: passkey.rpID, allowed: [passkey.credentialID]).first?.id
            else { return }
            id = found
        }
        let detail = try await service.item(id: id)
        let (body, rest) = draft(entry, keeping: detail)
        do {
            _ = try await service.save(id: id, revision: detail.row.revision, draft: body)
        } catch {
            report.failed += 1
        }
        await save(rest, title: detail.row.title, tags: entry.tags, service: service, report: &report)
    }

    /// The draft of an entry, and the details that do not fit on it. With `keeping` (a login),
    /// the stored fields stay as they are (a secret as nil keeps its value) and the entry adds
    /// what the item does not have.
    static func draft(_ entry: Entry, keeping detail: ItemDetail?) -> (draft: ItemDraft, rest: [Value]) {
        guard entry.kind == .login else {
            var fields: [DraftField] = []
            if let main = entry.main { fields.append(.named(main.label, main.value, secret: true)) }
            fields += entry.details.map { DraftField.detail($0.label, $0.value, secret: $0.secret) }
            return (
                ItemDraft(
                    title: entry.title, kind: entry.kind, notes: entry.notes, tags: Array(entry.tags.prefix(maxTags)),
                    fields: fields),
                []
            )
        }
        var fields: [DraftField] = []
        var names = Set<String>()
        var used = Set<String>()
        var details = 0
        var hasWebsite = false
        var hasOTP = false
        for field in detail?.fields ?? [] {
            names.insert(field.name)
            if field.role == .website { hasWebsite = true }
            if field.role == .totp { hasOTP = true }
            if field.custom {
                used.insert(field.label.lowercased())
                details += 1
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
        if !hasWebsite, let website, details < maxDetails {
            let label = uniqueLabel("Website", used: used)
            used.insert(label.lowercased())
            details += 1
            fields.append(.detail(label, website, secret: false))
        }
        var pool = entry.details
        if !hasOTP, let otp = entry.otp {
            if details < maxDetails {
                let label = uniqueLabel("One-time password", used: used)
                used.insert(label.lowercased())
                details += 1
                fields.append(.detail(label, otp, secret: true))
            } else {
                pool.insert(Value("One-time password", otp, secret: true), at: 0)
            }
        }
        var notes = [detail?.notes ?? "", entry.notes].filter { !$0.isEmpty }.joined(separator: "\n\n")
        if notes.utf8.count > maxNotesBytes, !entry.notes.isEmpty {
            notes = detail?.notes ?? ""
            pool.insert(Value("Note", entry.notes, secret: true), at: 0)
        }
        let (fitted, rest) = fit(pool, budget: max(0, maxDetails - details), used: used)
        fields += fitted.map { DraftField.detail($0.label, $0.value, secret: $0.secret) }
        var tags = detail?.row.tags ?? []
        for tag in entry.tags where !tags.contains(tag) { tags.append(tag) }
        return (
            ItemDraft(
                title: detail?.row.title ?? entry.title, kind: .login, notes: notes, tags: Array(tags.prefix(maxTags)),
                fields: fields),
            rest
        )
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
            var exported = ASImportableCredential.Passkey(
                credentialID: passkey.credentialID, relyingPartyIdentifier: passkey.rpID,
                userName: passkey.userName, userDisplayName: passkey.userDisplayName,
                userHandle: passkey.userHandle, key: passkey.key)
            // The PRF secrets and the large blob go with the passkey, so the other app keeps what
            // the website stored with them (iOS 26.4 and later carry them).
            if #available(iOS 26.4, macOS 26.4, *), passkey.prf != nil || passkey.largeBlob != nil {
                exported.fido2Extensions = ASImportableFIDO2Extensions(
                    hmacCredentials: passkey.prf.map {
                        ASImportableFIDO2HMACCredential(
                            algorithm: .sha256, credentialWithUV: $0.withUV, credentialWithoutUV: $0.withoutUV)
                    },
                    largeBlob: passkey.largeBlob.map {
                        ASImportableFIDO2LargeBlob(uncompressedSize: $0.uncompressedSize, data: $0.data)
                    })
            }
            credentials.append(.passkey(exported))
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
