// The AutoFill extension of Apassy (ADR 0023): fills one login or one-time code, signs in with a
// passkey, or saves a new passkey, after a fresh owner check, with the vault core in the
// `autofill` role (it never syncs). The suggestions come from `CredentialIdentitySync` in the app.

import ApassyVaultKit
import AuthenticationServices
import SwiftUI

final class CredentialProviderViewController: ASCredentialProviderViewController {
    private lazy var model = AutoFillModel { [weak self] outcome in
        self?.answer(outcome)
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        let host = UIHostingController(rootView: AutoFillRootView(model: model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        model.dismissed()
    }

    // MARK: - Requests of iOS

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.startList(for: serviceIdentifiers, kind: .password)
    }

    /// A website that takes passkeys: its passkeys first, then the logins.
    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        model.startPasskeyList(
            for: serviceIdentifiers,
            request: PasskeyAssertionContext(
                rpID: requestParameters.relyingPartyIdentifier, clientDataHash: requestParameters.clientDataHash,
                allowed: requestParameters.allowedCredentials,
                extensions: Self.extensions(requestParameters.extensionInput)))
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.startList(for: serviceIdentifiers, kind: .oneTimeCode)
    }

    /// Never fills or signs without the sheet: each one needs the owner check.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    /// A passkey is saved only after the owner check, so a conditional registration never runs.
    override func performWithoutUserInteractionIfPossible(passkeyRegistration registrationRequest: ASPasskeyCredentialRequest) {
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        let identity = credentialRequest.credentialIdentity
        switch credentialRequest.type {
        case .password:
            // The username is checked before a fill.
            model.startDirect(
                record: identity.recordIdentifier, user: (identity as? ASPasswordCredentialIdentity)?.user,
                serviceIdentifier: identity.serviceIdentifier, kind: .password)
        case .oneTimeCode:
            model.startDirect(
                record: identity.recordIdentifier, user: (identity as? ASOneTimeCodeCredentialIdentity)?.label,
                serviceIdentifier: identity.serviceIdentifier, kind: .oneTimeCode)
        case .passkeyAssertion:
            guard let request = credentialRequest as? ASPasskeyCredentialRequest,
                let passkey = identity as? ASPasskeyCredentialIdentity
            else {
                extensionContext.cancelRequest(withError: ASExtensionError(.failed))
                return
            }
            model.startPasskey(
                record: passkey.recordIdentifier, credentialID: passkey.credentialID,
                request: PasskeyAssertionContext(
                    rpID: passkey.relyingPartyIdentifier, clientDataHash: request.clientDataHash,
                    allowed: [passkey.credentialID], extensions: Self.extensions(request.extensionInput)))
        default:
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
        }
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
            let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        // The user handle is the account ID of the website; iOS puts the user name in the identity.
        model.startRegistration(
            PasskeyRegistrationContext(
                rpID: identity.relyingPartyIdentifier, userName: identity.userName, userDisplayName: identity.userName,
                userHandle: identity.userHandle, clientDataHash: request.clientDataHash,
                algorithms: request.supportedAlgorithms.map { $0.rawValue },
                excluded: request.excludedCredentials?.map(\.credentialID) ?? [],
                extensions: Self.extensions(request.extensionInput)))
    }

    override func prepareInterfaceForExtensionConfiguration() {
        model.startConfiguration()
    }

    // MARK: - WebAuthn extensions

    private static func extensions(_ input: ASPasskeyCredentialExtensionInput) -> PasskeyExtensionRequest {
        switch input {
        case .assertion(let assertion): extensions(assertion)
        case .registration(let registration):
            PasskeyExtensionRequest(
                largeBlob: registration.largeBlob.map {
                    $0.supportRequirement == .required ? .required : .preferred
                } ?? .none,
                prf: registration.prf != nil)
        case .none: PasskeyExtensionRequest()
        @unknown default: PasskeyExtensionRequest()
        }
    }

    private static func extensions(_ input: ASPasskeyAssertionCredentialExtensionInput?) -> PasskeyExtensionRequest {
        guard let input else { return PasskeyExtensionRequest() }
        let largeBlob: PasskeyExtensionRequest.LargeBlob
        switch input.largeBlob?.operation {
        case .read: largeBlob = .read
        case .write: largeBlob = .write
        case nil: largeBlob = .none
        @unknown default: largeBlob = .none
        }
        return PasskeyExtensionRequest(largeBlob: largeBlob, prf: input.prf != nil)
    }

    // MARK: - The answer

    private func answer(_ outcome: AutoFillOutcome) {
        switch outcome {
        case .password(let credential):
            extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
        case .oneTimeCode(let credential):
            extensionContext.completeOneTimeCodeRequest(using: credential, completionHandler: nil)
        case .passkeyAssertion(let credential):
            extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
        case .passkeyRegistration(let credential):
            extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
        case .cancelled:
            extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
        case .failed(let error):
            extensionContext.cancelRequest(withError: error)
        case .configured:
            extensionContext.completeExtensionConfigurationRequest()
        }
    }
}
