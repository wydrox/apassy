import AuthenticationServices
import CryptoKit
import Foundation
import Testing

@testable import ApassyVaultKit

// The import of Apple's credential exchange: items without login data, passkeys of every key type
// with their extension data, the attach of a passkey to a login of the vault, and the wire of the
// PRF and large blob members. Synthetic values only.

@Suite struct PasskeyKeyAndWireTests {
    @Test func importKeysOfEveryTypeAreCheckedLightly() throws {
        let p256 = P256.Signing.PrivateKey()
        let (normalized, type) = try PasskeyRequestCheck.importKey(p256.derRepresentation)
        #expect(type == .p256 && normalized == p256.derRepresentation)

        let p384 = P384.Signing.PrivateKey().derRepresentation
        let checked = try PasskeyRequestCheck.importKey(p384)
        #expect(checked.type == .p384 && checked.key == p384)

        let ed25519 = ed25519PKCS8(Curve25519.Signing.PrivateKey().rawRepresentation)
        let edKey = try PasskeyRequestCheck.importKey(ed25519)
        #expect(edKey.type == .ed25519 && edKey.key == ed25519)

        let rsa = try PasskeyRequestCheck.importKey(rsaPKCS8)
        #expect(rsa.type == .rsa && rsa.key == rsaPKCS8)

        // Damaged keys, a raw key, a curve that Apassy does not know, and trailing bytes.
        for bad in [
            Data([0x30, 0x03, 0x02, 0x01, 0x01]), Curve25519.Signing.PrivateKey().rawRepresentation,
            P521.Signing.PrivateKey().derRepresentation, ed25519 + Data([0]), Data(ed25519.prefix(20)),
            ed25519PKCS8(Data(repeating: 1, count: 31)),
        ] {
            #expect(throws: VaultError.self) { try PasskeyRequestCheck.importKey(bad) }
        }
    }

    @Test func assertionsDecodeTheNewMembersAndAnOlderCore() throws {
        let first = Data(repeating: 3, count: 32)
        let json = """
            {"credential_id": "AQID", "user_handle": "BAU=", "authenticator_data": "AA==", "signature": "AQ==",
             "algorithm": -8, "prf": {"first": "\(first.base64EncodedString())"}, "large_blob": {"data": "AQI="}}
            """
        let assertion = try JSONDecoder().decode(PasskeyAssertion.self, from: Data(json.utf8))
        #expect(assertion.algorithm == PasskeyAlgorithm.edDSA)
        #expect(assertion.prf == PasskeyPRFOutput(first: first, second: nil))
        #expect(assertion.largeBlob?.data == Data([1, 2]) && assertion.largeBlob?.written == nil)
        #expect(!"\(assertion)".contains("AQI") && "\(assertion)".contains("redacted"))

        let written = #"{"credential_id": "AQID", "user_handle": "", "authenticator_data": "", "signature": "", "large_blob": {"written": true}}"#
        #expect(try JSONDecoder().decode(PasskeyAssertion.self, from: Data(written.utf8)).largeBlob?.written == true)

        let older = #"{"credential_id": "AQID", "user_handle": "BAU=", "authenticator_data": "AA==", "signature": "AQ=="}"#
        let old = try JSONDecoder().decode(PasskeyAssertion.self, from: Data(older.utf8))
        #expect(old.algorithm == nil && old.prf == nil && old.largeBlob == nil)
    }

    @Test func exportedPasskeysCarryTheirExtensionData() throws {
        let json = """
            {"rp_id": "example.com", "credential_id": "AQID", "user_handle": "BA==", "user_name": "ada",
             "user_display_name": "Ada", "key": "AQ==", "algorithm": -35,
             "prf": {"with_uv": "AQ==", "without_uv": "Ag=="}, "large_blob": {"data": "Aw==", "uncompressed_size": 9}}
            """
        let passkey = try JSONDecoder().decode(ExportedPasskey.self, from: Data(json.utf8))
        #expect(passkey.algorithm == PasskeyAlgorithm.es384)
        #expect(passkey.prf == PasskeyPRFSecrets(withUV: Data([1]), withoutUV: Data([2])))
        #expect(passkey.largeBlob == PasskeyLargeBlob(data: Data([3]), uncompressedSize: 9))
        let older = #"{"rp_id": "example.com", "credential_id": "AQID", "user_handle": "BA==", "user_name": "", "user_display_name": "", "key": "AQ=="}"#
        let old = try JSONDecoder().decode(ExportedPasskey.self, from: Data(older.utf8))
        #expect(old.algorithm == nil && old.prf == nil && old.largeBlob == nil)
        #expect("\(PasskeyPRFSecrets(withUV: Data([1]), withoutUV: Data([2])))".contains("redacted"))
        #expect("\(PasskeyLargeBlob(data: Data([3]), uncompressedSize: 1))".contains("redacted"))
    }

    @Test func assertionExtensionsPickThePRFValuesOfTheCredential() {
        let general = PasskeyExtensionRequest.PRFValues(first: Data([1]))
        let own = PasskeyExtensionRequest.PRFValues(first: Data([2]), second: Data([3]))
        let request = PasskeyExtensionRequest(
            largeBlob: .write, prf: true, prfValues: general, prfValuesByCredential: [Data([9]): own],
            largeBlobWrite: Data([5]))
        #expect(request.prfInput(for: Data([9])) == own)
        #expect(request.prfInput(for: Data([8])) == general)
        #expect(request.largeBlobOperation == .write(Data([5])))
        #expect(PasskeyExtensionRequest(largeBlob: .read).largeBlobOperation == .read)
        // A write without data is not sent: the answer is a failed write.
        #expect(PasskeyExtensionRequest(largeBlob: .write).largeBlobOperation == nil)
        #expect(PasskeyExtensionRequest().prfInput(for: Data([9])) == nil)
        #expect(!"\(PasskeyPRFInput(first: Data([1]), hashed: false))".contains("1"))
    }
}

/// Swift Testing takes no `@available` test, so each test checks the OS and runs a case here.
@Suite struct CredentialExchangeImportTests {
    @Test func cardsWifiNotesAndCodesBecomeCustomItems() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try ImportCases().cardsWifiNotesAndCodesBecomeCustomItems()
    }

    @Test func documentsAddressesAndNamesAreHiddenAndOverflowIntoASecondItem() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try ImportCases().documentsAddressesAndNamesAreHiddenAndOverflowIntoASecondItem()
    }

    @Test func apiKeysAndSSHKeysKeepTheirKinds() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try ImportCases().apiKeysAndSSHKeysKeepTheirKinds()
    }

    @Test func customFieldsGeneratedPasswordsAndLoneUsernames() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try ImportCases().customFieldsGeneratedPasswordsAndLoneUsernames()
    }

    @Test func aLoginKeepsItsExtrasAndTheRestGoesToACustomItem() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try ImportCases().aLoginKeepsItsExtrasAndTheRestGoesToACustomItem()
    }

    @Test func labelsFitAndDifferAndValuesStayOutOfTitlesNotesAndTags() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try ImportCases().labelsFitAndDifferAndValuesStayOutOfTitlesNotesAndTags()
    }

    @Test func passkeysOfEveryKeyTypeAreKept() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try ImportCases().passkeysOfEveryKeyTypeAreKept()
    }

    @Test func passkeyExtensionDataIsKeptAndExported() throws {
        guard #available(macOS 26.4, iOS 26.4, *) else { return }
        try ExtensionCases().passkeyExtensionDataIsKeptAndExported()
    }

    @Test func attachMatchesOneActiveLoginWithoutAPasskey() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try ImportCases().attachMatchesOneActiveLoginWithoutAPasskey()
    }

    @Test func importAttachesAPasskeyToTheLoginOfTheVault() async throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try await ImportCases().importAttachesAPasskeyToTheLoginOfTheVault()
    }

    @Test func importSavesEveryKindIntoTheVault() async throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try await ImportCases().importSavesEveryKindIntoTheVault()
    }

    @Test func aPasskeyInTheVaultStillCompletesItsLogin() async throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try await FollowUpCases().aPasskeyInTheVaultStillCompletesItsLogin()
    }

    @Test func aStoredPasswordAndCodeStayAndDifferentImportedOnesAreKept() async throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try await FollowUpCases().aStoredPasswordAndCodeStayAndDifferentImportedOnesAreKept()
    }

    @Test func anAttachTargetThatGotAPasskeyMeanwhileMakesANewLogin() async throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try await FollowUpCases().anAttachTargetThatGotAPasskeyMeanwhileMakesANewLogin()
    }

    @Test func untitledLoginsTakeTheHostAndPersonalItemsHideTheirCustomFields() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try FollowUpCases().untitledLoginsTakeTheHostAndPersonalItemsHideTheirCustomFields()
    }

    @Test func ed25519SSHKeysAreWrittenInTheOpenSSHFormat() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try FollowUpCases().ed25519SSHKeysAreWrittenInTheOpenSSHFormat()
    }

    @Test func anOlderSystemWithholdsPasskeysWithExtensionData() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try FollowUpCases().anOlderSystemWithholdsPasskeysWithExtensionData()
    }

    @Test func theSummaryHasCountsOnly() {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        ImportCases().theSummaryHasCountsOnly()
    }
}

// MARK: - Helpers

private func ed25519PKCS8(_ seed: Data) -> Data {
    Data([0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, UInt8(seed.count)])
        + seed
}

/// The outer structure of an RSA PKCS #8 key with a stand-in RSAPrivateKey (the light check
/// reads the structure only).
private let rsaPKCS8 = Data([
    0x30, 0x19, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x04, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00,
])

/// The rules of the core's `build_draft` that an imported draft must keep.
private func expectVaultRules(_ draft: ItemDraft) {
    let builtin: Set<String> = [
        "service", "project", "token", "password", "private_key", "passphrase", "username", "host", "database",
        "public_key",
    ]
    #expect(!draft.title.isEmpty && draft.title.utf8.count <= 128)
    #expect(draft.notes.utf8.count <= 8192)
    #expect(draft.tags.count <= 32 && draft.tags.allSatisfy { !$0.isEmpty && $0.utf8.count <= 64 })
    let details = draft.fields.filter { $0.label != nil }
    #expect(details.count <= 10)
    #expect(details.allSatisfy { ($0.label ?? "").utf8.count <= 31 })
    #expect(Set(details.map { ($0.label ?? "").lowercased() }).count == details.count)
    #expect(draft.fields.allSatisfy { !($0.value ?? "").isEmpty })
    let named = draft.fields.filter { $0.label == nil }
    switch draft.kind {
    case .custom:
        #expect(named.count == 1)
        if let main = named.first, let name = main.name {
            #expect(main.secret && !builtin.contains(name) && !name.hasPrefix("x_"))
            #expect(name.utf8.count <= 64 && name.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") })
        }
    case .apiKey: #expect(named.contains { $0.name == "token" && $0.secret })
    case .sshKey: #expect(named.contains { $0.name == "private_key" && $0.secret })
    case .login:
        #expect(named.contains { $0.name == "username" })
        #expect(named.contains { $0.name == "password" && $0.secret })
    case .database: break
    }
}

@available(macOS 26.0, iOS 26.0, *)
private typealias V = CredentialExchangeImport.Value

@available(macOS 26.0, iOS 26.0, *)
private func data(_ items: [ASImportableItem]) -> ASExportedCredentialData {
    ASExportedCredentialData(
        accounts: [ASImportableAccount(id: Data([1]), userName: "", email: "", collections: [], items: items)],
        formatVersion: .v1, exporterRelyingPartyIdentifier: "exporter.example", exporterDisplayName: "Exporter",
        timestamp: Date())
}

@available(macOS 26.0, iOS 26.0, *)
private func field(_ value: String, _ type: ASImportableEditableField.FieldType = .string, label: String? = nil)
    -> ASImportableEditableField
{
    ASImportableEditableField(id: nil, fieldType: type, value: value, label: label)
}

@available(macOS 26.0, iOS 26.0, *)
private func item(_ id: UInt8, _ title: String, tags: [String] = [], url: String? = nil, _ credentials: [ASImportableCredential])
    -> ASImportableItem
{
    ASImportableItem(
        id: Data([id]), created: Date(), lastModified: Date(), title: title,
        scope: url.map { ASImportableCredentialScope(urls: [URL(string: $0)!]) }, credentials: credentials, tags: tags)
}

@available(macOS 26.0, iOS 26.0, *)
private func card(number: String? = "4111 1111 1111 1111") -> ASImportableCredential {
    .creditCard(
        .init(
            number: number.map { field($0, .concealedString) }, fullName: field("Ada Example"), cardType: field("Visa"),
            verificationNumber: field("123", .concealedString), pin: field("0000", .concealedString),
            expiryDate: field("2030-01", .yearMonth), validFrom: field("2025-01", .yearMonth)))
}

@available(macOS 26.0, iOS 26.0, *)
private func passkey(key: Data, id: Data = Data([1, 2, 3]), rpID: String = "example.com", user: String = "ada")
    -> ASImportableCredential
{
    .passkey(
        .init(
            credentialID: id, relyingPartyIdentifier: rpID, userName: user, userDisplayName: "Ada",
            userHandle: Data([4]), key: key))
}

@available(macOS 26.0, iOS 26.0, *)
private extension CredentialExchangeImport.Entry {
    var draft: ItemDraft { CredentialExchangeImport.draft(self, keeping: nil).draft }

    func detail(_ label: String) -> CredentialExchangeImport.Value? { details.first { $0.label == label } }
}

// MARK: - Cases

@available(macOS 26.0, iOS 26.0, *)
private struct ImportCases {
    func cardsWifiNotesAndCodesBecomeCustomItems() throws {
        let plan = CredentialExchangeImport.plan(
            data([
                item(1, "Visa", tags: ["finance"], [card()]),
                item(2, "", [card()]),
                item(3, "", [
                    .wifi(.init(
                        ssid: field("HomeNet"), networkSecurityType: field("wpa2-personal", .wifiNetworkSecurityType),
                        passphrase: field("synthetic-wifi-pass", .concealedString), hidden: field("true", .boolean))),
                ]),
                item(4, "Recovery", tags: ["home"], [.note(.init(content: field("synthetic note text")))]),
                item(5, "", [.totp(.init(secret: Data("Hello!".utf8), period: 30, digits: 6, userName: nil, algorithm: .sha1))]),
                item(6, "Linked", [.itemReference(.init(reference: ASImportableLinkedItem(item: Data([1]))))]),
                item(7, "Empty card", [.creditCard(.init(number: nil, fullName: nil, cardType: nil, verificationNumber: nil, pin: nil, expiryDate: nil, validFrom: nil))]),
            ]))
        #expect(plan.entries.count == 5)
        #expect(plan.unsupported == 2 && plan.invalid == 0)
        for entry in plan.entries { expectVaultRules(entry.draft) }

        let visa = plan.entries[0]
        #expect(visa.kind == .custom && visa.title == "Visa" && visa.tags == ["finance", "card"])
        // The first hidden value is the one main field of a Custom item.
        #expect(visa.main == V("card_number", "4111 1111 1111 1111", secret: true))
        #expect(visa.details.map(\.label) == ["Security code", "PIN", "Cardholder", "Expiry", "Valid from", "Card type"])
        #expect(visa.details.map(\.secret) == [true, true, true, true, true, false])
        #expect(visa.detail("Card type")?.value == "Visa")
        #expect(plan.entries[1].title == "Card")

        let wifi = plan.entries[2]
        #expect(wifi.title == "Wi-Fi network" && wifi.tags == ["wifi"])
        #expect(wifi.main == V("secret", "synthetic-wifi-pass", secret: true))
        #expect(wifi.details == [
            V("Network", "HomeNet", secret: false), V("Security", "wpa2-personal", secret: false),
            V("Hidden network", "Yes", secret: false),
        ])

        let note = plan.entries[3]
        #expect(note.kind == .custom && note.title == "Recovery" && note.tags == ["home", "note"])
        #expect(note.main == V("note", "synthetic note text", secret: true) && note.details.isEmpty && note.notes.isEmpty)

        let code = plan.entries[4]
        #expect(code.title == "One-time password" && code.tags.isEmpty)
        #expect(code.main?.label == "otp" && code.main?.value.hasPrefix("otpauth://totp/") == true)
    }

    func documentsAddressesAndNamesAreHiddenAndOverflowIntoASecondItem() throws {
        let passport = ASImportableCredential.passport(
            .init(
                issuingCountry: field("PL", .countryCode), passportType: field("P"), passportNumber: field("EA0000000"),
                nationalIdentificationNumber: field("00000000000"), nationality: field("Polish"),
                fullName: field("Ada Example"), birthDate: field("1990-01-01", .date), birthPlace: field("Krakow"),
                sex: field("F"), issueDate: field("2020-01-01", .date), expiryDate: field("2030-01-01", .date),
                issuingAuthority: field("Authority")))
        let identity = [
            ASImportableCredential.driversLicense(
                .init(
                    fullName: field("Ada Example"), birthDate: nil, issueDate: nil, expiryDate: nil,
                    issuingAuthority: nil, territory: field("Mazowieckie"), country: field("PL"),
                    licenseNumber: field("DL-0000"), licenseClass: field("B"))),
            .address(.init(
                streetAddress: field("1 Example St"), postalCode: field("00-001"), city: field("Warsaw"),
                territory: nil, country: nil, telephone: field("+48 000 000 000"))),
            .personName(.init(
                title: nil, given: field("Ada"), givenInformal: nil, given2: nil, surnamePrefix: nil,
                surname: field("Example"), surname2: nil, credentials: nil, generation: nil)),
        ]
        let plan = CredentialExchangeImport.plan(
            data([item(1, "Passport", [passport]), item(2, "", identity)]))
        for entry in plan.entries { expectVaultRules(entry.draft) }
        // The passport has 13 values: its main field and 10 details on the first item, the other
        // 2 on a second Custom item with the same title.
        #expect(plan.entries.count == 4)
        let first = plan.entries[0]
        let second = plan.entries[1]
        #expect(first.main == V("passport_number", "EA0000000", secret: true))
        #expect(first.detail("Document type") == V("Document type", "Passport", secret: false))
        #expect(first.detail("Issuing country") == V("Issuing country", "PL", secret: false))
        #expect(first.details.count == 10)
        #expect(first.details.filter { !$0.secret }.map(\.label) == ["Document type", "Issuing country"])
        #expect(second.title == "Passport" && second.tags == ["identity"] && first.tags == ["identity"])
        #expect(second.main == V("expiry_date", "2030-01-01", secret: true))
        #expect(second.details == [V("Issuing authority", "Authority", secret: true)])

        // A license, an address, and a name in one item: one tag, every value but the type and
        // the country hidden.
        let license = plan.entries[2]
        #expect(license.title == "Driver's license" && license.tags == ["identity"])
        #expect(license.main == V("license_number", "DL-0000", secret: true))
        #expect(license.details.filter { !$0.secret }.map(\.value) == ["Driver's license", "PL"])
        let rest = plan.entries[3]
        #expect(rest.title == "Driver's license" && rest.details.allSatisfy(\.secret))
        let all = (license.details + rest.details + [rest.main].compactMap { $0 }).map(\.value)
        #expect(all.contains("Mazowieckie") && all.contains("Warsaw") && all.contains("Example"))
    }

    func apiKeysAndSSHKeysKeepTheirKinds() throws {
        let der = Data((0..<48).map { UInt8($0) })
        let plan = CredentialExchangeImport.plan(
            data([
                item(1, "Stripe", url: "https://dashboard.stripe.example", [
                    .apiKey(.init(
                        key: field("sk_test_synthetic", .concealedString), userName: field("ada"), keyType: field("secret"),
                        url: field("https://api.stripe.example"), validFrom: nil, expiryDate: field("2030-01-01", .date))),
                ]),
                item(2, "", [.apiKey(.init(key: nil, userName: field("ada"), keyType: nil, url: nil, validFrom: nil, expiryDate: nil))]),
                item(3, "Deploy", [
                    .sshKey(.init(
                        keyType: "ssh-ed25519", privateKey: der, keyComment: "ada@laptop", creationDate: nil,
                        expiryDate: nil, keyGenerationSource: nil)),
                ]),
            ]))
        #expect(plan.entries.count == 3)
        for entry in plan.entries { expectVaultRules(entry.draft) }
        let api = plan.entries[0]
        #expect(api.kind == .apiKey && api.main == V("token", "sk_test_synthetic", secret: true))
        #expect(api.details.map(\.label) == ["Username", "URL", "Key type", "Expiry date", "Website"])
        #expect(api.details.allSatisfy { !$0.secret })
        // Without the key, the API key kind cannot take it.
        #expect(plan.entries[1].kind == .custom && plan.entries[1].title == "API key")

        let ssh = plan.entries[2]
        #expect(ssh.kind == .sshKey && ssh.main?.label == "private_key")
        let pem = try #require(ssh.main?.value)
        #expect(pem.hasPrefix("-----BEGIN PRIVATE KEY-----\n") && pem.hasSuffix("\n-----END PRIVATE KEY-----\n"))
        let body = pem.split(separator: "\n").dropFirst().dropLast().joined()
        #expect(Data(base64Encoded: body) == der)
        #expect(ssh.details == [V("Key type", "ssh-ed25519", secret: false), V("Comment", "ada@laptop", secret: false)])
    }

    func customFieldsGeneratedPasswordsAndLoneUsernames() throws {
        let fields = ASImportableCredential.customFields(
            .init(label: "Extra", fields: [
                field("synthetic-hidden", .concealedString, label: "Recovery key"),
                field("eu-west-1", label: "Region"),
                field("synthetic-text", label: "Security answer"),
                field("2020-01-01", .date, label: "Opened"),
                field("value", label: nil),
            ]))
        let plan = CredentialExchangeImport.plan(
            data([
                item(1, "Fields", [fields]),
                item(2, "", [.generatedPassword(.init(password: "synthetic-generated"))]),
                item(3, "Forum", [.basicAuthentication(.init(userName: field("bob")))]),
            ]))
        #expect(plan.entries.count == 3)
        for entry in plan.entries { expectVaultRules(entry.draft) }
        let custom = plan.entries[0]
        #expect(custom.main == V("recovery_key", "synthetic-hidden", secret: true))
        // A text field is visible only with a known plain label.
        #expect(custom.details == [
            V("Region", "eu-west-1", secret: false), V("Security answer", "synthetic-text", secret: true),
            V("Opened", "2020-01-01", secret: true), V("Extra", "value", secret: true),
        ])
        let generated = plan.entries[1]
        #expect(generated.title == "Generated password" && generated.main == V("secret", "synthetic-generated", secret: true))
        // A Custom item needs one secret main field: the username takes it.
        let forum = plan.entries[2]
        #expect(forum.kind == .custom && forum.main == V("account_name", "bob", secret: true))
    }

    func aLoginKeepsItsExtrasAndTheRestGoesToACustomItem() throws {
        let fields = ASImportableCredential.customFields(
            .init(fields: (1...4).map { field("synthetic-\($0)", .concealedString, label: "Answer \($0)") }))
        let plan = CredentialExchangeImport.plan(
            data([
                item(1, "Bank", tags: ["money"], url: "https://bank.example", [
                    .basicAuthentication(.init(userName: field("ada"), password: field("synthetic-pw", .concealedString))),
                    card(), fields,
                ]),
                item(2, "No user", url: "https://nouser.example", [
                    .basicAuthentication(.init(password: field("synthetic-pw2", .concealedString))),
                ]),
            ]))
        #expect(plan.entries.count == 3)
        for entry in plan.entries { expectVaultRules(entry.draft) }
        let login = plan.entries[0]
        #expect(login.kind == .login && login.password == "synthetic-pw" && login.tags == ["money", "card"])
        // The website takes one of the 10 details: 9 values of the 11 fit.
        #expect(login.details.count == 9)
        #expect(login.details.first == V("Card number", "4111 1111 1111 1111", secret: true))
        #expect(login.draft.fields.filter { $0.label != nil }.count == 10)
        let rest = plan.entries[1]
        #expect(rest.kind == .custom && rest.title == "Bank" && rest.tags == ["money", "card"])
        #expect(rest.main == V("answer_3", "synthetic-3", secret: true))
        #expect(rest.details == [V("Answer 4", "synthetic-4", secret: true)])
        // A password without a username: not a login of the vault, a Custom item.
        let noUser = plan.entries[2]
        #expect(noUser.kind == .custom && noUser.main == V("secret", "synthetic-pw2", secret: true))
        #expect(noUser.details == [V("Website", "https://nouser.example", secret: false)])
    }

    func labelsFitAndDifferAndValuesStayOutOfTitlesNotesAndTags() throws {
        let long = String(repeating: "é", count: 40)
        let fields = ASImportableCredential.customFields(
            .init(fields: [
                field("synthetic-a", .concealedString, label: "Main"),
                field("synthetic-b", .concealedString, label: long),
                field("synthetic-c", .concealedString, label: "Field"),
                field("synthetic-d", .concealedString, label: "field"),
                field("synthetic-e", .concealedString, label: " "),
            ]))
        let longTitle = String(repeating: "T", count: 200)
        let plan = CredentialExchangeImport.plan(
            data([item(1, longTitle, tags: ["", " tag ", String(repeating: "g", count: 80)], [fields])]))
        let entry = try #require(plan.entries.first)
        expectVaultRules(entry.draft)
        #expect(entry.title.utf8.count == 128)
        #expect(entry.tags == ["tag", String(repeating: "g", count: 64)])
        let labels = entry.details.map(\.label)
        #expect(labels[0] == String(repeating: "é", count: 15))
        #expect(labels[1...] == ["Field", "field 2", "Field 3"])
        for value in ["synthetic-a", "synthetic-b", "synthetic-c", "synthetic-d", "synthetic-e"] {
            #expect(!entry.title.contains(value) && !entry.notes.contains(value) && !entry.tags.contains(value))
        }
        #expect("\(entry)".contains("redacted") && !"\(entry.details[0])".contains("synthetic"))
    }

    func passkeysOfEveryKeyTypeAreKept() throws {
        let p384 = P384.Signing.PrivateKey().derRepresentation
        let ed = ed25519PKCS8(Curve25519.Signing.PrivateKey().rawRepresentation)
        let plan = CredentialExchangeImport.plan(
            data([
                item(1, "P-384", [passkey(key: p384, id: Data([1]))]),
                item(2, "Ed25519", [passkey(key: ed, id: Data([2]))]),
                item(3, "RSA", [passkey(key: rsaPKCS8, id: Data([3]))]),
                item(4, "Damaged", [passkey(key: Data([0x30, 0x00]), id: Data([4]))]),
            ]))
        #expect(plan.entries.compactMap(\.passkey?.key) == [p384, ed, rsaPKCS8])
        #expect(plan.invalid == 1 && plan.unsupported == 0)
    }

    func attachMatchesOneActiveLoginWithoutAPasskey() throws {
        func row(
            _ id: UInt64, user: String = "Ada ", site: String = "https://example.com/login", kind: ItemKind = .login,
            archived: Bool = false, hasPasskey: Bool = false, conflictOf: UInt64? = nil
        ) -> ItemRow {
            ItemRow(
                id: id, revision: 1, title: "t", kind: kind, subtitle: user, websites: [site], tags: [],
                archived: archived, hasTotp: false, conflictOf: conflictOf, addedAt: nil, changedAt: nil, usedAt: nil,
                hasPasskey: hasPasskey)
        }
        let account = PasskeyImportAccount(
            rpID: "example.com", credentialID: Data([1]), userHandle: Data([2]), userName: "ADA", userDisplayName: "",
            key: Data(), title: "t")
        let entry = CredentialExchangeImport.Entry(title: "t")
        let target = { (rows: [ItemRow]) in
            CredentialExchangeImport.attachTarget(for: entry, passkey: account, rows: rows)?.id
        }
        #expect(target([row(1)]) == 1)
        #expect(target([row(1, site: "EXAMPLE.com.")]) == 1)
        #expect(target([row(1), row(2)]) == nil)
        #expect(target([row(1, user: "bob")]) == nil)
        #expect(target([row(1, site: "https://www.example.com")]) == nil)
        #expect(target([row(1, kind: .apiKey)]) == nil)
        #expect(target([row(1, archived: true)]) == nil)
        #expect(target([row(1, hasPasskey: true)]) == nil)
        #expect(target([row(1, conflictOf: 9)]) == nil)
        // The ones that do not match do not count against the one that does.
        #expect(target([row(1), row(2, hasPasskey: true), row(3, user: "bob")]) == 1)
        // The basic-auth username matches too; the website of the item does not: the passkey
        // works only on its relying party.
        let other = CredentialExchangeImport.Entry(title: "t", website: "https://login.example.org", username: "bob")
        #expect(
            CredentialExchangeImport.attachTarget(
                for: other, passkey: account, rows: [row(5, user: "BOB", site: "login.example.org")]) == nil)
        #expect(
            CredentialExchangeImport.attachTarget(for: other, passkey: account, rows: [row(6, user: "BOB")])?.id == 6)
        let nameless = PasskeyImportAccount(
            rpID: "example.com", credentialID: Data([1]), userHandle: Data([2]), userName: "", userDisplayName: "",
            key: Data(), title: "t")
        #expect(CredentialExchangeImport.attachTarget(for: entry, passkey: nameless, rows: [row(1)]) == nil)
    }

    func importAttachesAPasskeyToTheLoginOfTheVault() async throws {
        let service = PreviewVaultService()
        let login = try await service.save(
            id: nil, revision: nil,
            draft: ItemDraft(
                title: "Example", kind: .login, notes: "", tags: [],
                fields: [
                    .named("username", "Ada", secret: false), .named("password", "synthetic-old", secret: true),
                    .detail("Website", "https://example.com/login", secret: false),
                ]))
        let before = try await service.items(archived: .all).count
        let key = P256.Signing.PrivateKey()
        let export = data([
            item(1, "Example", [
                .basicAuthentication(.init(userName: field("ada"), password: field("synthetic-new", .concealedString))),
                passkey(key: key.derRepresentation), card(),
            ]),
        ])
        let report = await CredentialExchangeImport.run(CredentialExchangeImport.plan(export), service: service)
        #expect(report.attached == 1 && report.passkeys == 1 && report.imported == 0 && report.failed == 0)
        #expect(report.keptStored == 1)
        #expect(try await service.items(archived: .all).count == before)
        let detail = try await service.item(id: login.id)
        #expect(detail.passkey?.credentialID == Data([1, 2, 3]) && detail.row.hasPasskey)
        // The stored fields stay; the login gets what it did not have, and the different imported
        // password is a hidden detail.
        #expect(try await service.reveal(id: login.id, field: "password") == "synthetic-old")
        let imported = try #require(detail.fields.first { $0.label == "Imported password" })
        #expect(imported.secret && imported.custom)
        #expect(try await service.reveal(id: login.id, field: imported.name) == "synthetic-new")
        #expect(detail.fields.contains { $0.label == "Card number" && $0.secret })
        #expect(detail.row.tags == ["card"])

        // Two logins match: no guess, a new login.
        let twice = PreviewVaultService()
        for _ in 0..<2 {
            _ = try await twice.save(
                id: nil, revision: nil,
                draft: ItemDraft(
                    title: "Example", kind: .login, notes: "", tags: [],
                    fields: [
                        .named("username", "ada", secret: false), .named("password", "synthetic-old", secret: true),
                        .detail("Website", "example.com", secret: false),
                    ]))
        }
        let again = await CredentialExchangeImport.run(CredentialExchangeImport.plan(export), service: twice)
        #expect(again.attached == 0 && again.imported == 1 && again.passkeys == 1)
    }

    func importSavesEveryKindIntoTheVault() async throws {
        let service = PreviewVaultService()
        let before = try await service.items(archived: .all).count
        let export = data([
            item(1, "Visa", [card()]),
            item(2, "Note", [.note(.init(content: field("synthetic note")))]),
            item(3, "Key", [.apiKey(.init(key: field("synthetic-token"), userName: nil, keyType: nil, url: nil, validFrom: nil, expiryDate: nil))]),
            item(4, "Linked", [.itemReference(.init(reference: ASImportableLinkedItem(item: Data([1]))))]),
        ])
        let plan = CredentialExchangeImport.plan(export)
        let report = await CredentialExchangeImport.run(plan, service: service)
        #expect(report.imported == 3 && report.failed == 0 && report.unsupported == 1)
        #expect(try await service.items(archived: .all).count == before + 3)
        let visa = try #require(try await service.items(archived: .no).first { $0.title == "Visa" })
        #expect(visa.kind == .custom && visa.tags == ["card"])
        #expect(try await service.reveal(id: visa.id, field: "card_number") == "4111 1111 1111 1111")
        #expect(report.summary == "Imported 3 items. 1 item has nothing that Apassy can keep.")
    }

    func theSummaryHasCountsOnly() {
        var report = CredentialExchangeImport.Report()
        report.imported = 3
        report.passkeys = 2
        report.attached = 1
        report.existing = 1
        report.invalid = 1
        report.failed = 1
        report.unsupported = 2
        #expect(
            report.summary
                == "Imported 3 items and 2 passkeys. 1 passkey went on a login that was in the vault already. "
                + "1 passkey was in the vault already. 1 passkey could not be used: the key or its extension data is "
                + "damaged or of a kind that Apassy does not know. 1 item could not be saved. "
                + "2 items have nothing that Apassy can keep.")
        var one = CredentialExchangeImport.Report()
        one.imported = 1
        #expect(one.summary == "Imported 1 item.")
        var kept = CredentialExchangeImport.Report()
        kept.existing = 2
        kept.completed = 2
        kept.keptStored = 1
        #expect(
            kept.summary
                == "Imported 0 items. 2 passkeys were in the vault already. 2 logins with such passkeys got the "
                + "fields that they lacked. 1 login kept its stored password or one-time password; the imported one "
                + "is a hidden detail.")
    }
}

@available(macOS 26.4, iOS 26.4, *)
private struct ExtensionCases {
    func passkeyExtensionDataIsKeptAndExported() throws {
        let key = P256.Signing.PrivateKey().derRepresentation
        let withUV = Data(repeating: 1, count: 32)
        let withoutUV = Data(repeating: 2, count: 32)
        let extensions = ASImportableFIDO2Extensions(
            hmacCredentials: ASImportableFIDO2HMACCredential(
                algorithm: .sha256, credentialWithUV: withUV, credentialWithoutUV: withoutUV),
            largeBlob: ASImportableFIDO2LargeBlob(uncompressedSize: 12, data: Data([9, 9, 9])))
        let kept = ASImportableCredential.passkey(
            .init(
                credentialID: Data([1]), relyingPartyIdentifier: "example.com", userName: "ada", userDisplayName: "Ada",
                userHandle: Data([4]), key: key, fido2Extensions: extensions))
        let damaged = ASImportableCredential.passkey(
            .init(
                credentialID: Data([2]), relyingPartyIdentifier: "example.com", userName: "ada", userDisplayName: "Ada",
                userHandle: Data([4]), key: key,
                fido2Extensions: ASImportableFIDO2Extensions(
                    largeBlob: ASImportableFIDO2LargeBlob(uncompressedSize: 12, data: Data()))))
        let plan = CredentialExchangeImport.plan(data([item(1, "Example", [kept]), item(2, "Damaged", [damaged])]))
        #expect(plan.entries.count == 1 && plan.invalid == 1)
        let account = try #require(plan.entries.first?.passkey)
        #expect(account.prf == PasskeyPRFSecrets(withUV: withUV, withoutUV: withoutUV))
        #expect(account.largeBlob == PasskeyLargeBlob(data: Data([9, 9, 9]), uncompressedSize: 12))
        #expect(!"\(account)".contains("ada"))

        // The export writes them back, so a transfer out keeps them.
        let exported = ExportedItem(
            id: 7, title: "Example",
            passkey: ExportedPasskey(
                rpID: "example.com", credentialID: Data([1]), userHandle: Data([4]), userName: "ada",
                userDisplayName: "Ada", key: key, algorithm: PasskeyAlgorithm.es256, prf: account.prf,
                largeBlob: account.largeBlob))
        let made = try #require(CredentialExchangeExport.item(of: exported, vaultID: "v1", now: Date()))
        let written = try #require(
            made.credentials.compactMap { credential -> ASImportableCredential.Passkey? in
                if case .passkey(let passkey) = credential { passkey } else { nil }
            }.first)
        #expect(written.fido2Extensions == extensions)
        let plain = ExportedItem(
            id: 8, title: "Plain",
            passkey: ExportedPasskey(
                rpID: "example.com", credentialID: Data([3]), userHandle: Data([4]), userName: "ada",
                userDisplayName: "Ada", key: key))
        let plainItem = try #require(CredentialExchangeExport.item(of: plain, vaultID: "v1", now: Date()))
        #expect(plainItem.credentials.allSatisfy { credential in
            if case .passkey(let passkey) = credential { passkey.fido2Extensions == nil } else { true }
        })
    }
}

@available(macOS 26.0, iOS 26.0, *)
private struct FollowUpCases {
    private let uri = "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP"

    /// A passkey-only login in `service`, with the passkey that `passkey(key:)` imports.
    private func passkeyLogin(_ service: PreviewVaultService, key: P256.Signing.PrivateKey) async throws -> UInt64 {
        let result = try await service.passkeyImport([
            PasskeyImportAccount(
                rpID: "example.com", credentialID: Data([1, 2, 3]), userHandle: Data([4]), userName: "ada",
                userDisplayName: "Ada", key: key.derRepresentation, title: "Example"),
        ])
        #expect(result.imported == 1)
        return try #require(try await service.passkeys(rpID: "example.com", allowed: [Data([1, 2, 3])]).first?.id)
    }

    func aPasskeyInTheVaultStillCompletesItsLogin() async throws {
        let service = PreviewVaultService()
        let key = P256.Signing.PrivateKey()
        let id = try await passkeyLogin(service, key: key)
        let before = try await service.items(archived: .all).count
        let export = data([
            item(1, "Example", [
                .basicAuthentication(.init(userName: field("ada"), password: field("synthetic-pw", .concealedString))),
                passkey(key: key.derRepresentation), card(),
            ]),
        ])
        let report = await CredentialExchangeImport.run(CredentialExchangeImport.plan(export), service: service)
        #expect(report.existing == 1 && report.completed == 1 && report.imported == 0 && report.passkeys == 0)
        #expect(report.failed == 0 && report.keptStored == 0)
        #expect(try await service.items(archived: .all).count == before)
        #expect(try await service.reveal(id: id, field: "password") == "synthetic-pw")
        #expect(try await service.item(id: id).fields.contains { $0.label == "Card number" })

        // The same import again changes nothing.
        let again = await CredentialExchangeImport.run(CredentialExchangeImport.plan(export), service: service)
        #expect(again.existing == 1 && again.completed == 0 && again.keptStored == 0)
    }

    func aStoredPasswordAndCodeStayAndDifferentImportedOnesAreKept() async throws {
        let service = PreviewVaultService()
        let key = P256.Signing.PrivateKey()
        let id = try await passkeyLogin(service, key: key)
        var detail = try await service.item(id: id)
        _ = try await service.save(
            id: id, revision: detail.row.revision,
            draft: ItemDraft(
                title: "Example", kind: .login, notes: "", tags: [],
                fields: [
                    .named("username", "ada", secret: false), .named("password", "synthetic-old", secret: true),
                    .detail("Website", "https://example.com", secret: false),
                    .detail("One-time password", uri, secret: true),
                ]))
        let otherSeed = ASImportableCredential.totp(
            .init(secret: Data("Other!".utf8), period: 30, digits: 6, userName: "ada", algorithm: .sha1))
        let export = data([
            item(1, "Example", [
                .basicAuthentication(.init(userName: field("ada"), password: field("synthetic-new", .concealedString))),
                passkey(key: key.derRepresentation), otherSeed,
            ]),
        ])
        let report = await CredentialExchangeImport.run(CredentialExchangeImport.plan(export), service: service)
        #expect(report.existing == 1 && report.completed == 1 && report.keptStored == 1 && report.failed == 0)
        detail = try await service.item(id: id)
        #expect(try await service.reveal(id: id, field: "password") == "synthetic-old")
        let password = try #require(detail.fields.first { $0.label == "Imported password" })
        #expect(password.secret && password.custom)
        #expect(try await service.reveal(id: id, field: password.name) == "synthetic-new")
        let code = try #require(detail.fields.first { $0.label == "One-time password (imported)" })
        // The label is a one-time password label (contract ios-core-v1, section 7), and the value
        // is an otpauth URI: the core reads it as a code.
        #expect(code.secret && code.role == .totp)
        #expect(try await service.reveal(id: id, field: code.name).hasPrefix("otpauth://totp/"))
        // The same import again: the imported values are there already, so nothing is added.
        let again = await CredentialExchangeImport.run(CredentialExchangeImport.plan(export), service: service)
        #expect(again.existing == 1 && again.completed == 0 && again.keptStored == 0)
        #expect(try await service.item(id: id).fields.count == detail.fields.count)

        // The same values: nothing new.
        let stored = CredentialExchangeImport.Stored(password: "synthetic-new", otp: "JBSW Y3DP EE")
        let entry = CredentialExchangeImport.Entry(
            title: "Example", username: "ada", password: "synthetic-new",
            otp: OTPAuthURI.make(secret: Data("Hello!".utf8), issuer: "Example", account: "ada"))
        let made = CredentialExchangeImport.draft(entry, keeping: detail, stored: stored)
        #expect(!made.keptStored)
        #expect(!made.draft.fields.contains { $0.label == "Imported password 2" || $0.label == "One-time password (imported) 2" })
        #expect(CredentialExchangeImport.sameOTP("JBSWY3DPEE", "otpauth://totp/x?secret=jbswy3dpee&digits=6"))
        #expect(!CredentialExchangeImport.sameOTP("JBSWY3DPEE", uri))
        #expect(!CredentialExchangeImport.sameOTP(nil, uri))
    }

    func anAttachTargetThatGotAPasskeyMeanwhileMakesANewLogin() async throws {
        let service = PreviewVaultService()
        let login = try await service.save(
            id: nil, revision: nil,
            draft: ItemDraft(
                title: "Example", kind: .login, notes: "", tags: [],
                fields: [
                    .named("username", "ada", secret: false), .named("password", "synthetic-old", secret: true),
                    .detail("Website", "https://example.com", secret: false),
                ]))
        // The core answers "exists" for the attach, but the passkey is not in the vault.
        await service.scriptPasskeyImportsForTesting([PasskeyImportResult(imported: 0, skippedExisting: 1, failed: 0)])
        let export = data([item(1, "Example", [passkey(key: P256.Signing.PrivateKey().derRepresentation)])])
        let report = await CredentialExchangeImport.run(CredentialExchangeImport.plan(export), service: service)
        let calls = await service.passkeyImportCallsForTesting()
        #expect(calls.map { $0.first?.attachID } == [login.id, nil])
        #expect(report.imported == 1 && report.passkeys == 1 && report.attached == 0 && report.existing == 0)
        #expect(try await service.item(id: login.id).passkey == nil)
    }

    func untitledLoginsTakeTheHostAndPersonalItemsHideTheirCustomFields() throws {
        let plain = ASImportableCredential.customFields(
            .init(fields: [field("Ada", label: "Name"), field("eu-west-1", label: "Region")]))
        let plan = CredentialExchangeImport.plan(
            data([
                item(1, "", url: "https://example.com/magic?token=synthetic-token", [
                    .basicAuthentication(.init(userName: field("ada"), password: field("synthetic-pw", .concealedString))),
                ]),
                item(2, "Visa", [card(), plain]),
                item(3, "Office", [
                    .wifi(.init(
                        ssid: field("Office"), networkSecurityType: nil,
                        passphrase: field("synthetic-wifi", .concealedString))),
                    plain,
                ]),
            ]))
        #expect(plan.entries.count == 3)
        #expect(plan.entries[0].title == "example.com")
        #expect(!plan.entries[0].title.contains("synthetic"))
        let visa = plan.entries[1]
        #expect(visa.detail("Name")?.secret == true && visa.detail("Region")?.secret == true)
        // A Wi-Fi network is not personal: a plain label stays visible.
        let office = plan.entries[2]
        #expect(office.detail("Name")?.secret == false && office.detail("Region")?.secret == false)
    }

    func ed25519SSHKeysAreWrittenInTheOpenSSHFormat() throws {
        let key = Curve25519.Signing.PrivateKey()
        let der = Data([0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])
            + key.rawRepresentation
        let text = try #require(CredentialExchangeImport.openSSH(ed25519: der, comment: "ada@laptop"))
        #expect(text.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----\n"))
        #expect(text.hasSuffix("\n-----END OPENSSH PRIVATE KEY-----\n"))
        let lines = text.split(separator: "\n").dropFirst().dropLast()
        #expect(lines.allSatisfy { $0.count <= 70 })
        var reader = SSHReader(bytes: [UInt8](try #require(Data(base64Encoded: lines.joined()))))
        let magic = reader.take(15)
        let cipher = reader.text()
        let kdf = reader.text()
        let kdfOptions = reader.field()
        let keys = reader.uint32()
        let publicField = reader.field()
        let secretField = reader.field()
        #expect(magic == Array("openssh-key-v1".utf8) + [0])
        #expect(cipher == "none" && kdf == "none" && kdfOptions == [] && keys == 1)
        #expect(reader.atEnd)
        let publicKey = [UInt8](key.publicKey.rawRepresentation)
        var publicBlob = SSHReader(bytes: try #require(publicField))
        let publicType = publicBlob.text()
        let publicBytes = publicBlob.field()
        #expect(publicType == "ssh-ed25519" && publicBytes == publicKey && publicBlob.atEnd)
        let secret = try #require(secretField)
        #expect(secret.count % 8 == 0)
        var section = SSHReader(bytes: secret)
        let check1 = section.uint32()
        let check2 = section.uint32()
        let type = section.text()
        let sectionPublic = section.field()
        let privateBytes = section.field()
        let comment = section.text()
        let padding = section.rest()
        #expect(check1 != nil && check1 == check2)
        #expect(type == "ssh-ed25519" && sectionPublic == publicKey)
        #expect(privateBytes == [UInt8](key.rawRepresentation) + publicKey)
        #expect(comment == "ada@laptop")
        #expect(padding == (0..<padding.count).map { UInt8($0 + 1) })

        // Through the import: the kind SSH key with the OpenSSH text; RSA and ECDSA stay PEM.
        let plan = CredentialExchangeImport.plan(
            data([
                item(1, "Deploy", [
                    .sshKey(.init(
                        keyType: "ssh-ed25519", privateKey: der, keyComment: "ada@laptop", creationDate: nil,
                        expiryDate: nil, keyGenerationSource: nil)),
                ]),
            ]))
        #expect(plan.entries.first?.kind == .sshKey)
        #expect(plan.entries.first?.main?.value.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----") == true)
        #expect(CredentialExchangeImport.openSSH(ed25519: rsaPKCS8, comment: "") == nil)
        #expect(CredentialExchangeImport.openSSH(ed25519: P256.Signing.PrivateKey().derRepresentation, comment: "") == nil)
    }

    func anOlderSystemWithholdsPasskeysWithExtensionData() throws {
        let key = P256.Signing.PrivateKey().derRepresentation
        func passkey(_ id: UInt8, prf: Bool) -> ExportedPasskey {
            ExportedPasskey(
                rpID: "example.com", credentialID: Data([id]), userHandle: Data([4]), userName: "ada",
                userDisplayName: "Ada", key: key,
                prf: prf ? PasskeyPRFSecrets(withUV: Data(repeating: 1, count: 32), withoutUV: Data(repeating: 2, count: 32)) : nil)
        }
        let withPassword = ExportedItem(id: 1, title: "Example", username: "ada", password: "synthetic-pw", passkey: passkey(1, prf: true))
        let passkeyOnly = ExportedItem(id: 2, title: "Only", passkey: passkey(2, prf: true))
        let plain = ExportedItem(id: 3, title: "Plain", passkey: passkey(3, prf: false))
        let export = CredentialExport(items: [withPassword, passkeyOnly, plain], skipped: 0)
        #expect(CredentialExchangeExport.withheldPasskeys(export, carriesExtensions: false) == 2)
        #expect(CredentialExchangeExport.withheldPasskeys(export, carriesExtensions: true) == 0)

        let old = CredentialExchangeExport.data(export, vaultID: "v1", carriesExtensions: false)
        let items = old.accounts.flatMap(\.items)
        // The login keeps its password without the passkey; a passkey-only login is left out.
        #expect(items.map(\.title) == ["Example", "Plain"])
        let passkeys = items.flatMap { item in
            item.credentials.compactMap { credential -> Data? in
                if case .passkey(let passkey) = credential { passkey.credentialID } else { nil }
            }
        }
        #expect(passkeys == [Data([3])])
    }
}

/// Reads the SSH wire format (RFC 4251): uint32 lengths and strings.
private struct SSHReader {
    var bytes: [UInt8]
    var index = 0

    var atEnd: Bool { index == bytes.count }

    mutating func take(_ count: Int) -> [UInt8]? {
        guard count >= 0, index + count <= bytes.count else { return nil }
        defer { index += count }
        return Array(bytes[index..<(index + count)])
    }

    mutating func uint32() -> UInt32? {
        guard let four = take(4) else { return nil }
        return four.reduce(0) { ($0 << 8) | UInt32($1) }
    }

    mutating func field() -> [UInt8]? {
        guard let length = uint32() else { return nil }
        return take(Int(length))
    }

    mutating func text() -> String? { field().map { String(decoding: $0, as: UTF8.self) } }

    mutating func rest() -> [UInt8] {
        defer { index = bytes.count }
        return Array(bytes[index...])
    }
}
