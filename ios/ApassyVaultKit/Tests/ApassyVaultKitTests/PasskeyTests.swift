import AuthenticationServices
import CryptoKit
import Foundation
import Testing

@testable import ApassyVaultKit

// Passkeys on the Swift side: the wire models, the checks of a request, the synthetic
// authenticator of the preview vault, and Apple's credential exchange. Synthetic values only.

private let hash = Data(repeating: 7, count: 32)

@Suite struct PasskeyWireTests {
    @Test func rowsAndDetailsDecodeThePasskeyWithoutAKey() throws {
        let json = """
            {"id": 3, "revision": 2, "title": "Example", "kind": "login", "subtitle": "ada",
             "websites": [], "tags": [], "archived": false, "has_totp": false, "has_passkey": true,
             "has_password": false, "conflict_of": null, "added_at": null, "changed_at": null, "used_at": null,
             "notes": "", "fields": [],
             "passkey": {"rp_id": "example.com", "user_name": "ada", "user_display_name": "Ada",
                         "credential_id": "AQID", "user_handle": "BAU="}}
            """
        let detail = try JSONDecoder().decode(ItemDetail.self, from: Data(json.utf8))
        #expect(detail.row.hasPasskey)
        #expect(detail.row.hasPassword == false)
        #expect(detail.passkey?.rpID == "example.com")
        #expect(detail.passkey?.credentialID == Data([1, 2, 3]))
        #expect(detail.passkey?.userHandle == Data([4, 5]))
        #expect(detail.passkey?.accountName == "ada")
    }

    @Test func anOlderCoreHasNoPasskeys() throws {
        let row = """
            {"id": 3, "revision": 2, "title": "Example", "kind": "login", "subtitle": "",
             "websites": [], "tags": [], "archived": false, "has_totp": false}
            """
        #expect(try JSONDecoder().decode(ItemRow.self, from: Data(row.utf8)).hasPasskey == false)
        // An older core does not say if there is a password. That is "unknown", not "no".
        #expect(try JSONDecoder().decode(ItemRow.self, from: Data(row.utf8)).hasPassword == nil)
        let identities = #"{"identities": [{"id": 1, "username": "u", "host": "a.com"}]}"#
        let set = try JSONDecoder().decode(IdentitySet.self, from: Data(identities.utf8))
        #expect(set.passwords.count == 1)
        #expect(set.passkeys.isEmpty && set.codes.isEmpty)
    }

    @Test func identitiesCarryPasskeysAndCodes() throws {
        let json = """
            {"identities": [],
             "passkeys": [{"id": 4, "title": "Example", "rp_id": "example.com", "user_name": "ada",
                           "user_display_name": "Ada", "credential_id": "AQID", "user_handle": "BAU="}],
             "totp": [{"id": 5, "title": "GitHub", "username": "", "host": "github.com"}]}
            """
        let set = try JSONDecoder().decode(IdentitySet.self, from: Data(json.utf8))
        #expect(set.passkeys == [PasskeyIdentity(id: 4, rpID: "example.com", userName: "ada", credentialID: Data([1, 2, 3]), userHandle: Data([4, 5]))])
        #expect(set.codes.first?.label == "GitHub")
    }

    @Test func theCoreErrorsOfPasskeysHaveTheirCodes() {
        #expect(VaultError.Code(rawValue: "excluded") == .excluded)
        #expect(VaultError.Code(rawValue: "unsupported_algorithm") == .unsupportedAlgorithm)
        #expect(VaultError.Code(rawValue: "exists") == .exists)
        #expect(VaultError.Code(rawValue: "bad_key") == .badKey)
    }

    @Test func keysAreNotPrinted() {
        let account = PasskeyImportAccount(
            rpID: "example.com", credentialID: Data([1]), userHandle: Data([2]), userName: "ada", userDisplayName: "",
            key: Data([9, 9, 9]), title: "t")
        #expect(!"\(account)".contains("ada"))
        #expect("\(CredentialExport(items: [], skipped: 0))".contains("redacted"))
    }
}

@Suite struct PasskeyRequestCheckTests {
    @Test func aRegistrationNeedsES256AndAValidRequest() throws {
        let none = PasskeyExtensionRequest()
        _ = try PasskeyRequestCheck.registration(
            rpID: "example.com", userHandle: Data([1]), clientDataHash: hash, algorithms: [-8, -7], extensions: none)
        _ = try PasskeyRequestCheck.registration(
            rpID: "example.com", userHandle: Data([1]), clientDataHash: hash, algorithms: [], extensions: none)
        #expect(throws: PasskeyRequestError.unsupportedAlgorithm) {
            try PasskeyRequestCheck.registration(
                rpID: "example.com", userHandle: Data([1]), clientDataHash: hash, algorithms: [-257, -8], extensions: none)
        }
        #expect(throws: PasskeyRequestError.badClientDataHash) {
            try PasskeyRequestCheck.registration(
                rpID: "example.com", userHandle: Data([1]), clientDataHash: Data(count: 31), algorithms: [-7], extensions: none)
        }
        #expect(throws: PasskeyRequestError.badUserHandle) {
            try PasskeyRequestCheck.registration(
                rpID: "example.com", userHandle: Data(count: 65), clientDataHash: hash, algorithms: [-7], extensions: none)
        }
        #expect(throws: PasskeyRequestError.badRelyingParty) {
            try PasskeyRequestCheck.registration(
                rpID: "https://example.com", userHandle: Data([1]), clientDataHash: hash, algorithms: [-7], extensions: none)
        }
    }

    @Test func aRequiredExtensionFailsAndAnOptionalOneIsAnsweredAsUnsupported() throws {
        #expect(throws: PasskeyRequestError.unsupportedExtension("large blob storage")) {
            try PasskeyRequestCheck.registration(
                rpID: "example.com", userHandle: Data([1]), clientDataHash: hash, algorithms: [-7],
                extensions: PasskeyExtensionRequest(largeBlob: .required))
        }
        let answer = try PasskeyRequestCheck.registration(
            rpID: "example.com", userHandle: Data([1]), clientDataHash: hash, algorithms: [-7],
            extensions: PasskeyExtensionRequest(largeBlob: .preferred, prf: true))
        #expect(answer.largeBlobUnsupported && answer.prfUnsupported)
        let read = try PasskeyRequestCheck.assertion(
            rpID: "example.com", credentialID: Data([1]), clientDataHash: hash,
            extensions: PasskeyExtensionRequest(largeBlob: .read, prf: true))
        #expect(read.largeBlobReadEmpty && !read.prfUnsupported)
        let write = try PasskeyRequestCheck.assertion(
            rpID: "example.com", credentialID: nil, clientDataHash: hash, extensions: PasskeyExtensionRequest(largeBlob: .write))
        #expect(write.largeBlobWriteFailed)
        #expect(throws: PasskeyRequestError.badCredentialID) {
            try PasskeyRequestCheck.assertion(
                rpID: "example.com", credentialID: Data(), clientDataHash: hash, extensions: PasskeyExtensionRequest())
        }
    }

    @Test func importedKeysAreNormalizedPKCS8() throws {
        let key = P256.Signing.PrivateKey()
        let normalized = try PasskeyRequestCheck.normalizedKey(key.derRepresentation)
        #expect(normalized == key.derRepresentation)
        #expect(try P256.Signing.PrivateKey(derRepresentation: normalized).rawRepresentation == key.rawRepresentation)
        #expect(throws: VaultError.self) { try PasskeyRequestCheck.normalizedKey(Data([0x30, 0x03, 0x02, 0x01, 0x01])) }
        let ed25519 = Curve25519.Signing.PrivateKey()
        #expect(throws: VaultError.self) { try PasskeyRequestCheck.normalizedKey(ed25519.rawRepresentation) }
    }

    @Test func otpURIsUseBase32() {
        #expect(OTPAuthURI.base32(Data("Hello!".utf8)) == "JBSWY3DPEE")
        #expect(OTPAuthURI.decodeBase32("JBSWY3DPEE") == Data("Hello!".utf8))
        let uri = OTPAuthURI.make(secret: Data("Hello!".utf8), issuer: "Git Hub", account: "ada@example.com")
        #expect(uri == "otpauth://totp/Git%20Hub:ada%40example.com?secret=JBSWY3DPEE&issuer=Git%20Hub&algorithm=SHA1&digits=6&period=30")
    }
}

@Suite struct PreviewPasskeyTests {
    private func registration(_ service: PreviewVaultService, excluded: [Data] = []) async throws -> PasskeyCreated {
        try await service.passkeyRegister(
            PasskeyRegistration(
                rpID: "example.com", userName: "ada", userDisplayName: "Ada", userHandle: Data([1, 2]),
                clientDataHash: hash, algorithms: [-7], excluded: excluded, attach: nil, title: "Example"))
    }

    @Test func aRegisteredPasskeySignsAssertionsThatVerify() async throws {
        let service = PreviewVaultService()
        let created = try await registration(service)
        #expect(created.credentialID.count == 32)
        // "none" attestation: a CBOR map of three entries that holds the authenticator data.
        #expect(created.attestationObject.first == 0xA3)
        let found = try await service.passkeys(rpID: "example.com", allowed: [])
        #expect(found.map(\.id) == [created.id])
        #expect(try await service.passkeys(rpID: "other.example", allowed: []).isEmpty)
        #expect(try await service.passkeys(rpID: "example.com", allowed: [Data([9])]).isEmpty)

        let assertion = try await service.passkeyAssert(
            PasskeyAssertionRequest(id: created.id, rpID: "example.com", credentialID: created.credentialID, clientDataHash: hash))
        #expect(assertion.userHandle == Data([1, 2]))
        #expect(assertion.authenticatorData.prefix(32) == Data(SHA256.hash(data: Data("example.com".utf8))))
        #expect(assertion.authenticatorData[32] == 0x05)

        let export = try await service.credentialExport()
        let key = try #require(export.items.first { $0.id == created.id }?.passkey?.key)
        let publicKey = try P256.Signing.PrivateKey(derRepresentation: key).publicKey
        let signature = try P256.Signing.ECDSASignature(derRepresentation: assertion.signature)
        #expect(publicKey.isValidSignature(signature, for: assertion.authenticatorData + hash))

        await #expect(throws: VaultError.self) {
            try await service.passkeyAssert(
                PasskeyAssertionRequest(id: created.id, rpID: "evil.example", credentialID: created.credentialID, clientDataHash: hash))
        }
        let detail = try await service.item(id: created.id)
        #expect(detail.passkey?.rpID == "example.com")
        #expect(!detail.fields.contains { $0.name.hasPrefix("passkey_") })
    }

    @Test func anExcludedCredentialIsRefused() async throws {
        let service = PreviewVaultService()
        let created = try await registration(service)
        await #expect(throws: VaultError(.excluded, "This account has a passkey in the vault already.")) {
            _ = try await registration(service, excluded: [created.credentialID])
        }
    }

    @Test func aPasskeyOnlyLoginKeepsItsPasskeyThroughAnEdit() async throws {
        let service = PreviewVaultService()
        let created = try await registration(service)
        var detail = try await service.item(id: created.id)
        let draft = ItemDraft(
            title: "Renamed", kind: .login, notes: "n", tags: [],
            fields: detail.fields.map { .named($0.name, $0.value, secret: $0.secret) })
        _ = try await service.save(id: created.id, revision: detail.row.revision, draft: draft)
        detail = try await service.item(id: created.id)
        #expect(detail.row.title == "Renamed")
        #expect(detail.passkey != nil && detail.row.hasPasskey)
        let reserved = ItemDraft(
            title: "x", kind: .login, notes: "", tags: [], fields: [.named("passkey_key", "k", secret: true)])
        await #expect(throws: VaultError.self) {
            _ = try await service.save(id: created.id, revision: detail.row.revision, draft: reserved)
        }
    }
}

/// Swift Testing takes no `@available` test, so each test checks the OS and runs a case here.
@Suite struct CredentialExchangeTests {
    @Test func importPlansLoginsCodesAndPasskeysAndCountsTheRest() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try CredentialExchangeCases().importPlansLoginsCodesAndPasskeysAndCountsTheRest()
    }

    @Test func importSavesIntoTheVaultAndSkipsWhatItHas() async throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try await CredentialExchangeCases().importSavesIntoTheVaultAndSkipsWhatItHas()
    }

    @Test func exportRoundTripsThroughImport() async throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { return }
        try await CredentialExchangeCases().exportRoundTripsThroughImport()
    }
}

@available(macOS 26.0, iOS 26.0, *)
private struct CredentialExchangeCases {
    private func passkeyCredential(key: Data, rpID: String = "example.com") -> ASImportableCredential {
        .passkey(
            .init(
                credentialID: Data([1, 2, 3]), relyingPartyIdentifier: rpID, userName: "ada", userDisplayName: "Ada",
                userHandle: Data([4]), key: key))
    }

    private func data(_ items: [ASImportableItem]) -> ASExportedCredentialData {
        ASExportedCredentialData(
            accounts: [ASImportableAccount(id: Data([1]), userName: "", email: "", collections: [], items: items)],
            formatVersion: .v1, exporterRelyingPartyIdentifier: "exporter.example", exporterDisplayName: "Exporter",
            timestamp: Date())
    }

    private func field(_ value: String, _ type: ASImportableEditableField.FieldType = .string) -> ASImportableEditableField {
        ASImportableEditableField(id: nil, fieldType: type, value: value)
    }

    func importPlansLoginsCodesAndPasskeysAndCountsTheRest() throws {
        let key = P256.Signing.PrivateKey()
        let items = [
            ASImportableItem(
                id: Data([1]), created: Date(), lastModified: Date(), title: "Example",
                scope: ASImportableCredentialScope(urls: [URL(string: "https://example.com/login")!]),
                credentials: [
                    .basicAuthentication(.init(userName: field("ada"), password: field("synthetic-pw", .concealedString))),
                    passkeyCredential(key: key.derRepresentation),
                    .totp(.init(secret: Data("Hello!".utf8), period: 30, digits: 6, userName: "ada", algorithm: .sha1)),
                ]),
            ASImportableItem(
                id: Data([2]), created: Date(), lastModified: Date(), title: "Bad key",
                credentials: [passkeyCredential(key: Data([1, 2, 3]))]),
            ASImportableItem(
                id: Data([3]), created: Date(), lastModified: Date(), title: "Card",
                credentials: [.creditCard(.init(number: field("4111"), fullName: nil, cardType: nil, verificationNumber: nil, pin: nil, expiryDate: nil, validFrom: nil))]),
            ASImportableItem(
                id: Data([4]), created: Date(), lastModified: Date(), title: "Forum",
                credentials: [.basicAuthentication(.init(userName: field("bob"), password: field("synthetic-pw2")))]),
        ]
        let plan = CredentialExchangeImport.plan(data(items))
        #expect(plan.entries.count == 2)
        #expect(plan.invalid == 1)
        #expect(plan.unsupported == 1)
        #expect(plan.exporter == "Exporter")
        let first = try #require(plan.entries.first)
        #expect(first.passkey?.key == key.derRepresentation)
        #expect(first.password == "synthetic-pw")
        #expect(first.otp?.hasPrefix("otpauth://totp/") == true)
        #expect(first.website == "https://example.com/login")
    }

    func importSavesIntoTheVaultAndSkipsWhatItHas() async throws {
        let service = PreviewVaultService()
        let key = P256.Signing.PrivateKey()
        let items = [
            ASImportableItem(
                id: Data([1]), created: Date(), lastModified: Date(), title: "Example",
                credentials: [
                    .basicAuthentication(.init(userName: field("ada"), password: field("synthetic-pw"))),
                    passkeyCredential(key: key.derRepresentation),
                    .totp(.init(secret: Data("Hello!".utf8), period: 30, digits: 6, userName: "ada", algorithm: .sha1)),
                ]),
            ASImportableItem(
                id: Data([2]), created: Date(), lastModified: Date(), title: "Forum",
                credentials: [.basicAuthentication(.init(userName: field("bob"), password: field("synthetic-pw2")))]),
        ]
        let plan = CredentialExchangeImport.plan(data(items))
        let report = await CredentialExchangeImport.run(plan, service: service)
        #expect(report.imported == 2 && report.passkeys == 1 && report.failed == 0)
        let id = try #require(try await service.passkeys(rpID: "example.com", allowed: []).first?.id)
        let detail = try await service.item(id: id)
        #expect(detail.passkey != nil)
        #expect(try await service.reveal(id: id, field: "password") == "synthetic-pw")
        #expect(detail.row.hasTotp)
        #expect(detail.row.websites == ["https://example.com"])

        let again = await CredentialExchangeImport.run(CredentialExchangeImport.plan(data(Array(items.prefix(1)))), service: service)
        #expect(again.existing == 1 && again.imported == 0)
        #expect(!again.summary.contains("ada"))
    }

    func exportRoundTripsThroughImport() async throws {
        let source = PreviewVaultService()
        let created = try await source.passkeyRegister(
            PasskeyRegistration(
                rpID: "example.com", userName: "ada", userDisplayName: "Ada", userHandle: Data([1, 2]),
                clientDataHash: hash, algorithms: [-7], excluded: [], attach: nil, title: "Example"))
        let export = try await source.credentialExport()
        let data = CredentialExchangeExport.data(export, vaultID: "v1")
        #expect(data.exporterDisplayName == "Apassy")
        let items = data.accounts.flatMap(\.items)
        #expect(items.contains { item in item.credentials.contains { if case .passkey = $0 { true } else { false } } })
        #expect(items.contains { item in item.credentials.contains { if case .totp = $0 { true } else { false } } })
        // The same item gets the same ID at each export, and the ID does not show the item ID.
        #expect(CredentialExchangeExport.data(export, vaultID: "v1").accounts[0].items.map(\.id) == items.map(\.id))

        // The data survives the JSON of the format, and a new vault takes it.
        let decoded = try JSONDecoder().decode(ASExportedCredentialData.self, from: try JSONEncoder().encode(data))
        let target = PreviewVaultService(empty: false, unlocked: true)
        for row in try await target.items(archived: .all) { try await target.delete(id: row.id, revision: row.revision) }
        let report = await CredentialExchangeImport.run(CredentialExchangeImport.plan(decoded), service: target)
        #expect(report.passkeys == 1 && report.failed == 0 && report.invalid == 0)
        let moved = try #require(try await target.passkeys(rpID: "example.com", allowed: [created.credentialID]).first)
        let assertion = try await target.passkeyAssert(
            PasskeyAssertionRequest(id: moved.id, rpID: "example.com", credentialID: created.credentialID, clientDataHash: hash))
        let key = try #require(export.items.first { $0.id == created.id }?.passkey?.key)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: assertion.signature)
        #expect(try P256.Signing.PrivateKey(derRepresentation: key).publicKey
            .isValidSignature(signature, for: assertion.authenticatorData + hash))
    }
}

private let totpURI = "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP"

/// A login with a passkey, notes, a tag, a website, and a one-time password, with or without a
/// password.
private func passkeyLogin(_ service: PreviewVaultService, password: String?) async throws -> UInt64 {
    let created = try await service.passkeyRegister(
        PasskeyRegistration(
            rpID: "example.com", userName: "ada", userDisplayName: "Ada", userHandle: Data([1, 2]),
            clientDataHash: hash, algorithms: [-7], excluded: [], attach: nil, title: "Example"))
    let detail = try await service.item(id: created.id)
    var fields: [DraftField] = [
        .named("username", "ada", secret: false),
        .detail("Website", "example.com", secret: false),
        .detail("One-time password", totpURI, secret: true),
    ]
    if let password { fields.append(.named("password", password, secret: true)) }
    let draft = ItemDraft(title: "Example", kind: .login, notes: "recovery: see safe", tags: ["work"], fields: fields)
    _ = try await service.save(id: created.id, revision: detail.row.revision, draft: draft)
    return created.id
}

/// A detail as the wire of the core gives it, with the password metadata as given.
private func wireDetail(hasPassword: String?, fields: String) throws -> ItemDetail {
    let flag = hasPassword.map { #""has_password": \#($0),"# } ?? ""
    let json = """
        {"id": 9, "revision": 4, "title": "Example", "kind": "login", "subtitle": "ada",
         "websites": [], "tags": [], "archived": false, "has_totp": false, "has_passkey": true, \(flag)
         "conflict_of": null, "added_at": null, "changed_at": null, "used_at": null,
         "notes": "keep", "fields": [\(fields)],
         "passkey": {"rp_id": "example.com", "user_name": "ada", "user_display_name": "Ada",
                     "credential_id": "AQID", "user_handle": "BAU="}}
        """
    return try JSONDecoder().decode(ItemDetail.self, from: Data(json.utf8))
}

private let passwordField =
    #"{"name": "password", "label": "Password", "secret": true, "value": null, "role": "password", "custom": false}"#

@Suite struct PasskeyRemovalPlanTests {
    @Test func aLoginWithAPasswordKeepsEveryFieldWhenThePasskeyGoes() async throws {
        let service = PreviewVaultService()
        let id = try await passkeyLogin(service, password: "synthetic-Pw-1!")
        let detail = try await service.item(id: id)
        let plan = try #require(PasskeyRemovalPlan(detail: detail))
        #expect(plan.effect == .removesPasskey && !plan.deletesLogin)
        #expect(plan.itemID == id && plan.revision == detail.row.revision)

        try await service.passkeyRemove(id: plan.itemID, revision: plan.revision)
        let after = try await service.item(id: id)
        #expect(after.passkey == nil && !after.row.hasPasskey)
        #expect(after.notes == "recovery: see safe" && after.row.tags == ["work"])
        #expect(after.row.hasTotp)
        #expect(try await service.reveal(id: id, field: "password") == "synthetic-Pw-1!")
    }

    @Test func aPasskeyOnlyLoginIsDeletedWholeWithItsCodesAndNotes() async throws {
        let service = PreviewVaultService()
        let id = try await passkeyLogin(service, password: nil)
        let detail = try await service.item(id: id)
        #expect(detail.row.hasTotp && detail.notes == "recovery: see safe")
        let plan = try #require(PasskeyRemovalPlan(detail: detail))
        #expect(plan.effect == .deletesLogin && plan.deletesLogin)

        try await service.passkeyRemove(id: plan.itemID, revision: plan.revision)
        await #expect(throws: VaultError.self) { _ = try await service.item(id: id) }
    }

    @Test func theDeletingPlanIsNamedAsADeletionAndTheOtherIsNot() async throws {
        let service = PreviewVaultService()
        let deleting = try #require(
            PasskeyRemovalPlan(detail: try await service.item(id: try await passkeyLogin(service, password: nil))))
        let keeping = try #require(
            PasskeyRemovalPlan(detail: try await service.item(id: try await passkeyLogin(service, password: "synthetic-Pw-1!"))))
        // Each part that the owner reads differs, so the passkey wording cannot hide a deletion.
        #expect(deleting.actionTitle != keeping.actionTitle)
        #expect(deleting.dialogTitle != keeping.dialogTitle)
        #expect(deleting.message != keeping.message)
        #expect(deleting.ownerReason != keeping.ownerReason)
        #expect(deleting.systemImage != keeping.systemImage)
        // The owner check and the dialog name the item.
        #expect(deleting.ownerReason.contains(deleting.itemTitle) && deleting.dialogTitle.contains(deleting.itemTitle))
    }

    @Test func aStoredPasswordWithoutAValueDeletesTheLoginWhole() async throws {
        let service = PreviewVaultService()
        let id = try await passkeyLogin(service, password: "synthetic-Pw-1!")
        // The field is there, as in an older import, but it holds nothing.
        try await service.storeEmptyPasswordForTesting(id: id)
        let detail = try await service.item(id: id)
        #expect(detail.fields.contains { $0.name == "password" && $0.secret })
        #expect(detail.row.hasPassword == false)
        let plan = try #require(PasskeyRemovalPlan(detail: detail))
        #expect(plan.effect == .deletesLogin && plan.deletesLogin)
        #expect(plan.actionTitle == "Delete login" && plan.message.contains("deletes the entire login"))

        try await service.passkeyRemove(id: plan.itemID, revision: plan.revision)
        await #expect(throws: VaultError.self) { _ = try await service.item(id: id) }
    }

    @Test func theRowKeepsTrackOfThePasswordThatTheServiceStores() async throws {
        let service = PreviewVaultService()
        let with = try await service.item(id: try await passkeyLogin(service, password: "synthetic-Pw-1!"))
        #expect(with.row.hasPassword == true)
        let without = try await service.item(id: try await passkeyLogin(service, password: nil))
        #expect(without.row.hasPassword == false)
        // A password that the owner adds turns the row to "yes" and the plan to "keeps".
        _ = try await service.save(
            id: without.id, revision: without.row.revision,
            draft: ItemDraft(
                title: "Example", kind: .login, notes: "", tags: [],
                fields: [.named("username", "ada", secret: false), .named("password", "synthetic-Pw-2!", secret: true)]))
        let added = try await service.item(id: without.id)
        #expect(added.row.hasPassword == true)
        #expect(PasskeyRemovalPlan(detail: added)?.effect == .removesPasskey)
        // The list says the same, and neither answer holds the value.
        let listed = try await service.items(archived: .no).first { $0.id == without.id }
        #expect(listed?.hasPassword == true)
        let encoded = String(decoding: try JSONEncoder().encode(added), as: UTF8.self)
        #expect(encoded.contains("\"has_password\":true") && !encoded.contains("synthetic-Pw-2!"))
    }

    @Test func aCoreThatDoesNotSayIfThereIsAPasswordNeverPromisesToKeepTheLogin() throws {
        // A password field is listed, but the old core did not check its value: the plan must warn.
        let unknown = try #require(PasskeyRemovalPlan(detail: try wireDetail(hasPassword: nil, fields: passwordField)))
        #expect(unknown.effect == .mayDeleteLogin && unknown.deletesLogin)
        #expect(unknown.actionTitle == "Delete login" && unknown.systemImage == "trash")
        #expect(unknown.message.contains("deletes the entire login") && !unknown.message.contains("keeps its password"))
        #expect(unknown.itemID == 9 && unknown.revision == 4)
        // "Yes" from the core, but the fields do not show the password: trust neither.
        let disagree = try #require(PasskeyRemovalPlan(detail: try wireDetail(hasPassword: "true", fields: "")))
        #expect(disagree.effect == .mayDeleteLogin)
        // "No" from the core is "no", whatever the fields say.
        let empty = try #require(PasskeyRemovalPlan(detail: try wireDetail(hasPassword: "false", fields: passwordField)))
        #expect(empty.effect == .deletesLogin)
        // "Yes" with the field: the only case that keeps the login.
        let kept = try #require(PasskeyRemovalPlan(detail: try wireDetail(hasPassword: "true", fields: passwordField)))
        #expect(kept.effect == .removesPasskey && !kept.deletesLogin)
        // The three plans read differently, so the owner never sees the keeping words on a deletion.
        #expect(Set([unknown.message, empty.message, kept.message]).count == 3)
        #expect(Set([unknown.ownerReason, empty.ownerReason, kept.ownerReason]).count == 3)
    }

    @Test func theRevisionThatTheOwnerSawIsTheOneThatActs() async throws {
        let service = PreviewVaultService()
        let id = try await passkeyLogin(service, password: nil)
        let plan = try #require(PasskeyRemovalPlan(detail: try await service.item(id: id)))
        // The login changed after the dialog opened: the old plan must not delete the new version.
        let detail = try await service.item(id: id)
        _ = try await service.save(
            id: id, revision: detail.row.revision,
            draft: ItemDraft(
                title: "Example", kind: .login, notes: "new note", tags: [],
                fields: detail.fields.map { .named($0.name, $0.value, secret: $0.secret) }))
        await #expect(throws: VaultError.self) { try await service.passkeyRemove(id: plan.itemID, revision: plan.revision) }
        #expect(try await service.item(id: id).notes == "new note")
    }

    @Test func anItemWithoutAPasskeyHasNoPlan() async throws {
        let service = PreviewVaultService(empty: false, unlocked: true)
        let rows = try await service.items(archived: .no)
        let detail = try await service.item(id: try #require(rows.first { !$0.hasPasskey }).id)
        #expect(PasskeyRemovalPlan(detail: detail) == nil)
    }
}

@Suite struct PasskeyIdentityFilterTests {
    private func identity(_ id: UInt64, rp: String, credential: UInt8) -> PasskeyIdentity {
        PasskeyIdentity(id: id, rpID: rp, userName: "ada", credentialID: Data([credential]), userHandle: Data([1]))
    }

    @Test func equalCredentialIDsOfDifferentWebsitesAreBothKept() {
        let kept = PasskeyIdentityFilter.unique([
            identity(1, rp: "example.com", credential: 7), identity(2, rp: "other.example", credential: 7),
        ])
        #expect(kept.map(\.id) == [1, 2])
    }

    @Test func theSameWebsiteAndCredentialIDGivesOneIdentityAndKeepsTheOrder() {
        let kept = PasskeyIdentityFilter.unique([
            identity(3, rp: "example.com", credential: 9), identity(1, rp: "example.com", credential: 7),
            identity(2, rp: "example.com", credential: 7), identity(4, rp: "other.example", credential: 9),
        ])
        #expect(kept.map(\.id) == [3, 1, 4])
    }

    @Test func anIdentityCarriesNoKeyMaterial() throws {
        let data = try JSONEncoder().encode(identity(1, rp: "example.com", credential: 1))
        let keys = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any]).keys
        #expect(Set(keys) == ["id", "rp_id", "user_name", "credential_id", "user_handle"])
    }
}
