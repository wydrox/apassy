// The identities of the vault for the system (QuickType bar, the passkey sheet, the
// code suggestions). Only metadata: website, user name, credential ID, user handle,
// item ID. No password, no code, no key.
//
// Only a process with the AutoFill entitlement of this provider may write the store:
// the extension, or the containing app. The Rust app forbids unsafe code and cannot
// call AuthenticationServices, so the extension replaces the whole list each time it
// runs: when the owner turns AutoFill on (configuration), and at the start of every
// request. The app answers `credential_identities` with all passkeys (not filtered by
// website), the logins with a password, and the logins with a one-time code.

import AuthenticationServices
import Foundation

/// More identities than this are not sent to the system.
let maxIdentities = 20_000

@MainActor
enum IdentitySync {
    /// Ask the app for the identities and replace the store. Returns the number stored.
    static func refresh(_ send: (Data) async throws -> Data) async throws -> Int {
        let answer = try decodeAnswer(try await send(try encodeCall(IdentitiesCall())), as: IdentitiesAnswer.self)
        let identities = makeIdentities(answer)
        let store = ASCredentialIdentityStore.shared
        guard await store.state().isEnabled else {
            return 0
        }
        try await store.replaceCredentialIdentities(identities)
        return identities.count
    }

    static func makeIdentities(_ answer: IdentitiesAnswer) -> [any ASCredentialIdentity] {
        var result: [any ASCredentialIdentity] = []
        for passkey in answer.passkeys {
            guard isRelyingPartyHost(passkey.rpId),
                  let credential = wireBytes(passkey.credentialId, max: 1023),
                  let handle = wireBytes(passkey.userHandle, max: 64)
            else {
                continue
            }
            let name = visibleText(passkey.userName.isEmpty ? passkey.userDisplayName : passkey.userName, max: 128)
            result.append(ASPasskeyCredentialIdentity(
                relyingPartyIdentifier: passkey.rpId, userName: name, credentialID: credential, userHandle: handle,
                recordIdentifier: String(passkey.id)))
        }
        for login in answer.identities {
            guard let service = serviceIdentifier(login.host) else { continue }
            result.append(ASPasswordCredentialIdentity(
                serviceIdentifier: service, user: visibleText(login.username, max: 128), recordIdentifier: String(login.id)))
        }
        for code in answer.totp {
            guard let service = serviceIdentifier(code.host) else { continue }
            let label = visibleText(code.username.isEmpty ? code.title : code.username, max: 128)
            result.append(ASOneTimeCodeCredentialIdentity(
                serviceIdentifier: service, label: label, recordIdentifier: String(code.id)))
        }
        return Array(result.prefix(maxIdentities))
    }

    /// A host as the core writes it ("example.com" or "example.com:8443").
    static func serviceIdentifier(_ host: String) -> ASCredentialServiceIdentifier? {
        let parts = host.split(separator: ":", omittingEmptySubsequences: false)
        guard let name = parts.first, isRelyingPartyHost(String(name)) else { return nil }
        if parts.count == 1 {
            return ASCredentialServiceIdentifier(identifier: host, type: .domain)
        }
        guard parts.count == 2, let port = UInt16(parts[1]), port > 0 else { return nil }
        return ASCredentialServiceIdentifier(identifier: "https://\(host)", type: .URL)
    }

    static func isRelyingPartyHost(_ host: String) -> Bool {
        !host.isEmpty && host.utf8.count <= 253 && !host.hasPrefix(".") && !host.hasSuffix(".")
            && host.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x41 && $0 <= 0x5A) || $0 == 0x2D || $0 == 0x2E || $0 == 0x5F }
    }
}
