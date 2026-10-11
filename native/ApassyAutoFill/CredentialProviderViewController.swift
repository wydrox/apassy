// The AutoFill credential provider of Apassy on the Mac (com.wydrox.apassy.autofill).
// It fills a password or a one-time code, signs in with a passkey, and saves a new
// passkey. Every one of these needs a fresh owner check in the Apassy app, so the
// provider never answers without its sheet, and it supports no conditional
// registration. See docs/operations/mac-passkeys.md.
//
// The principal class has a fixed Objective-C name, so Info.plist does not depend on
// the Swift module name.

import AuthenticationServices
import SwiftUI

@objc(ApassyCredentialProviderViewController)
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private lazy var model = ProviderModel { [weak self] outcome in
        self?.answer(outcome)
    }

    override func loadView() {
        let host = NSHostingView(rootView: ProviderRootView(model: model))
        host.frame = NSRect(x: 0, y: 0, width: 440, height: 380)
        view = host
        preferredContentSize = NSSize(width: 440, height: 380)
    }

    override func viewDidDisappear() {
        super.viewDidDisappear()
        model.dismissed()
    }

    // MARK: - Lists

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.startList(domains: Self.domains(serviceIdentifiers), kind: .password)
    }

    /// A website that takes passkeys: its passkeys first, then its passwords.
    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        model.startPasskeyList(
            domains: Self.domains(serviceIdentifiers),
            request: AssertionRequest(
                rpID: requestParameters.relyingPartyIdentifier, clientDataHash: requestParameters.clientDataHash,
                allowed: requestParameters.allowedCredentials))
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.startList(domains: Self.domains(serviceIdentifiers), kind: .oneTimeCode)
    }

    // MARK: - No answer without the sheet

    /// Each fill and each signature needs the owner check in Apassy.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    /// No conditional registration: a passkey is saved only after the owner check.
    override func performWithoutUserInteractionIfPossible(passkeyRegistration registrationRequest: ASPasskeyCredentialRequest) {
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    // MARK: - One identity, with the sheet

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        let identity = credentialRequest.credentialIdentity
        switch credentialRequest.type {
        case .password:
            guard let password = identity as? ASPasswordCredentialIdentity else {
                return cancel(.credentialIdentityNotFound)
            }
            model.startDirect(
                record: password.recordIdentifier, user: password.user,
                domains: Self.domains([password.serviceIdentifier]), kind: .password)
        case .oneTimeCode:
            guard let code = identity as? ASOneTimeCodeCredentialIdentity else {
                return cancel(.credentialIdentityNotFound)
            }
            model.startDirect(
                record: code.recordIdentifier, user: code.label, domains: Self.domains([code.serviceIdentifier]),
                kind: .oneTimeCode)
        case .passkeyAssertion:
            guard let request = credentialRequest as? ASPasskeyCredentialRequest,
                  let passkey = identity as? ASPasskeyCredentialIdentity
            else {
                return cancel(.credentialIdentityNotFound)
            }
            model.startDirectPasskey(
                record: passkey.recordIdentifier, credentialID: passkey.credentialID, userName: passkey.userName,
                request: AssertionRequest(
                    rpID: passkey.relyingPartyIdentifier, clientDataHash: request.clientDataHash,
                    allowed: [passkey.credentialID]))
        default:
            cancel(.failed)
        }
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        else {
            return cancel(.failed)
        }
        var needsLargeBlob = false
        if case .registration(let input) = request.extensionInput {
            needsLargeBlob = input.largeBlob?.supportRequirement == .required
        }
        // macOS names the account in the identity; it has no separate display name.
        model.startRegistration(RegistrationRequest(
            rpID: identity.relyingPartyIdentifier, userName: identity.userName, userHandle: identity.userHandle,
            clientDataHash: request.clientDataHash, algorithms: request.supportedAlgorithms.map { $0.rawValue },
            excluded: request.excludedCredentials?.map(\.credentialID) ?? [], needsLargeBlob: needsLargeBlob))
    }

    /// The owner turned on Apassy in System Settings: fill the identity store.
    override func prepareInterfaceForExtensionConfiguration() {
        model.startConfiguration()
    }

    // MARK: - The answer

    private func cancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: ASExtensionError(code))
    }

    private func answer(_ outcome: ProviderOutcome) {
        switch outcome {
        case .password(let credential):
            extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
        case .oneTimeCode(let credential):
            extensionContext.completeOneTimeCodeRequest(using: credential, completionHandler: nil)
        case .passkeyAssertion(let credential):
            extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
        case .passkeyRegistration(let credential):
            extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
        case .configured:
            extensionContext.completeExtensionConfigurationRequest()
        case .cancelled:
            cancel(.userCanceled)
        case .failed(let code):
            cancel(code)
        }
    }

    /// The websites of the request, as the core reads them (a domain or a URL).
    private static func domains(_ services: [ASCredentialServiceIdentifier]) -> [String] {
        let domains = services.compactMap { service -> String? in
            switch service.type {
            case .domain, .URL: service.identifier
            default: nil
            }
        }
        return Array(domains.prefix(16))
    }
}
