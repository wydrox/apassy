import ApassyVaultKit
import CryptoKit
import Foundation
import Testing

@testable import ApassyVaultCore

/// The passkey calls over the real core (macOS slice of the XCFramework), as the app and the
/// AutoFill extension make them. Synthetic keys and accounts only.
@Suite struct CorePasskeyTests {
    private let hash = Data(SHA256.hash(data: Data("synthetic client data".utf8)))

    private func vault() async throws -> (CoreVaultService, URL) {
        let dir = FileManager.default.temporaryDirectory.appending(path: "apassy-core-pk-\(UUID().uuidString)")
        let core = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .app)
        _ = try await core.createLocalVault(name: "Personal", passphrase: "synthetic-swift-pass")
        return (core, dir)
    }

    @Test func aNewPasskeySignsAndStaysOutOfTheFields() async throws {
        let (core, dir) = try await vault()
        defer { try? FileManager.default.removeItem(at: dir) }
        let created = try await core.passkeyRegister(
            PasskeyRegistration(
                rpID: "example.com", userName: "ada", userDisplayName: "Ada", userHandle: Data([1, 2, 3]),
                clientDataHash: hash, algorithms: [-8, -7], excluded: [], attach: nil, title: "Example"))
        #expect(created.credentialID.count == 32)
        #expect(!created.attestationObject.isEmpty)

        let listed = try await core.passkeys(rpID: "example.com", allowed: [created.credentialID])
        #expect(listed.map(\.id) == [created.id])
        #expect(try await core.passkeys(rpID: "other.example", allowed: []).isEmpty)

        let detail = try await core.item(id: created.id)
        #expect(detail.passkey?.rpID == "example.com")
        #expect(detail.row.hasPasskey)
        #expect(!detail.fields.contains { $0.name.hasPrefix("passkey_") })
        let identities = try await core.identitySet()
        #expect(identities.passkeys.map(\.credentialID) == [created.credentialID])

        let assertion = try await core.passkeyAssert(
            PasskeyAssertionRequest(id: created.id, rpID: "example.com", credentialID: created.credentialID, clientDataHash: hash))
        #expect(assertion.userHandle == Data([1, 2, 3]))
        #expect(assertion.authenticatorData.prefix(32) == Data(SHA256.hash(data: Data("example.com".utf8))))
        await #expect(throws: VaultError.self) {
            try await core.passkeyAssert(
                PasskeyAssertionRequest(id: created.id, rpID: "evil.example", credentialID: created.credentialID, clientDataHash: hash))
        }

        do {
            _ = try await core.passkeyRegister(
                PasskeyRegistration(
                    rpID: "example.com", userName: "ada", userDisplayName: "Ada", userHandle: Data([1, 2, 3]),
                    clientDataHash: hash, algorithms: [-7], excluded: [created.credentialID], attach: nil, title: "Again"))
            Issue.record("an excluded passkey was made")
        } catch let error as VaultError {
            #expect(error.code == .excluded)
        }
        do {
            _ = try await core.passkeyRegister(
                PasskeyRegistration(
                    rpID: "example.com", userName: "bob", userDisplayName: "", userHandle: Data([9]),
                    clientDataHash: hash, algorithms: [-257], excluded: [], attach: nil, title: "RSA"))
            Issue.record("a passkey without ES256 was made")
        } catch let error as VaultError {
            #expect(error.code == .unsupportedAlgorithm)
        }
    }

    @Test func anImportedKeySignsWhatItsPublicKeyVerifies() async throws {
        let (core, dir) = try await vault()
        defer { try? FileManager.default.removeItem(at: dir) }
        let key = P256.Signing.PrivateKey()
        let account = PasskeyImportAccount(
            rpID: "example.com", credentialID: Data([7, 7, 7]), userHandle: Data([5]), userName: "ada",
            userDisplayName: "Ada", key: try PasskeyRequestCheck.normalizedKey(key.derRepresentation), title: "Example")
        #expect(try await core.passkeyImport([account]) == PasskeyImportResult(imported: 1, skippedExisting: 0, failed: 0))
        #expect(try await core.passkeyImport([account]) == PasskeyImportResult(imported: 0, skippedExisting: 1, failed: 0))

        let id = try #require(try await core.passkeys(rpID: "example.com", allowed: [Data([7, 7, 7])]).first?.id)
        let assertion = try await core.passkeyAssert(
            PasskeyAssertionRequest(id: id, rpID: "example.com", credentialID: Data([7, 7, 7]), clientDataHash: hash))
        let signature = try P256.Signing.ECDSASignature(derRepresentation: assertion.signature)
        #expect(key.publicKey.isValidSignature(signature, for: assertion.authenticatorData + hash))

        // A generic edit adds a password and keeps the passkey.
        let detail = try await core.item(id: id)
        let draft = ItemDraft(
            title: "Example", kind: .login, notes: "", tags: [],
            fields: [.named("username", "ada", secret: false), .named("password", "synthetic-Pw-1!", secret: true)])
        _ = try await core.save(id: id, revision: detail.row.revision, draft: draft)
        #expect(try await core.item(id: id).passkey != nil)

        // Removal keeps the login.
        let edited = try await core.item(id: id)
        try await core.passkeyRemove(id: id, revision: edited.row.revision)
        #expect(try await core.item(id: id).passkey == nil)
        #expect(try await core.passkeys(rpID: "example.com", allowed: []).isEmpty)
    }

    /// The core decides what removal does; `PasskeyRemovalPlan` must say the same.
    @Test func removalDeletesAPasswordlessLoginWholeAndKeepsOneWithAPassword() async throws {
        let (core, dir) = try await vault()
        defer { try? FileManager.default.removeItem(at: dir) }
        func login(rp: String, password: String?) async throws -> UInt64 {
            let created = try await core.passkeyRegister(
                PasskeyRegistration(
                    rpID: rp, userName: "ada", userDisplayName: "Ada", userHandle: Data([1, 2, 3]),
                    clientDataHash: hash, algorithms: [-7], excluded: [], attach: nil, title: "Login \(rp)"))
            let detail = try await core.item(id: created.id)
            var fields: [DraftField] = [
                .named("username", "ada", secret: false),
                .detail("Website", rp, secret: false),
                .detail("One-time password", "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP", secret: true),
            ]
            if let password { fields.append(.named("password", password, secret: true)) }
            let draft = ItemDraft(title: "Login \(rp)", kind: .login, notes: "recovery note", tags: ["work"], fields: fields)
            _ = try await core.save(id: created.id, revision: detail.row.revision, draft: draft)
            return created.id
        }

        // With a password: the plan keeps the login, and the core keeps every field.
        let kept = try await login(rp: "keep.example", password: "synthetic-Pw-1!")
        let keepPlan = try #require(PasskeyRemovalPlan(detail: try await core.item(id: kept)))
        #expect(keepPlan.effect == .removesPasskey)
        try await core.passkeyRemove(id: keepPlan.itemID, revision: keepPlan.revision)
        let after = try await core.item(id: kept)
        #expect(after.passkey == nil && after.notes == "recovery note" && after.row.tags == ["work"] && after.row.hasTotp)
        #expect(try await core.reveal(id: kept, field: "password") == "synthetic-Pw-1!")

        // Without one: the plan says the item is deleted, and the core deletes it with its code.
        let lost = try await login(rp: "lose.example", password: nil)
        let lostDetail = try await core.item(id: lost)
        #expect(lostDetail.row.hasTotp && lostDetail.notes == "recovery note")
        let deletePlan = try #require(PasskeyRemovalPlan(detail: lostDetail))
        #expect(deletePlan.effect == .deletesLogin)
        try await core.passkeyRemove(id: deletePlan.itemID, revision: deletePlan.revision)
        await #expect(throws: VaultError.self) { _ = try await core.item(id: lost) }
        #expect(try await core.item(id: kept).row.title == "Login keep.example")
    }

    @Test func theExportHandsOverTheKeys() async throws {
        let (core, dir) = try await vault()
        defer { try? FileManager.default.removeItem(at: dir) }
        let key = P256.Signing.PrivateKey()
        _ = try await core.passkeyImport([
            PasskeyImportAccount(
                rpID: "example.com", credentialID: Data([7]), userHandle: Data([5]), userName: "ada",
                userDisplayName: "Ada", key: key.derRepresentation, title: "Example")
        ])
        let login = ItemDraft(
            title: "GitHub", kind: .login, notes: "", tags: [],
            fields: [
                .named("username", "octocat", secret: false), .named("password", "synthetic-Pw-1!", secret: true),
                .detail("Website", "github.com", secret: false),
                .detail("One-time password", "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP", secret: true),
            ])
        _ = try await core.save(id: nil, revision: nil, draft: login)
        let export = try await core.credentialExport()
        let passkey = try #require(export.items.compactMap(\.passkey).first)
        #expect(try P256.Signing.PrivateKey(derRepresentation: passkey.key).rawRepresentation == key.rawRepresentation)
        let github = try #require(export.items.first { $0.title == "GitHub" })
        #expect(github.password == "synthetic-Pw-1!")
        #expect(github.totp?.secret == OTPAuthURI.decodeBase32("JBSWY3DPEHPK3PXP"))
        // The data goes to Apple's format without loss of the key.
        if #available(macOS 26.0, *) {
            let data = CredentialExchangeExport.data(export, vaultID: "v")
            #expect(data.accounts[0].items.count == 2)
        }
    }

    @Test func autoFillCannotImportRemoveOrExport() async throws {
        let (core, dir) = try await vault()
        defer { try? FileManager.default.removeItem(at: dir) }
        try await core.lock()
        let autofill = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .autofill)
        await #expect(throws: VaultError.self) { try await autofill.credentialExport() }
        await #expect(throws: VaultError.self) { try await autofill.passkeyRemove(id: 1, revision: 1) }
        await #expect(throws: VaultError.self) { try await autofill.passkeyImport([]) }
    }
}
