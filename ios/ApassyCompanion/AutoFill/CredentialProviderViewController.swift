// The AutoFill extension of Apassy (ADR 0023): fills one login or one-time code after a
// fresh owner check, with the vault core in the `autofill` role (it never syncs and never
// writes). The QuickType suggestions come from `CredentialIdentitySync` in the app.

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

    /// Apassy has no passkeys: a passkey request lists the passwords.
    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier], requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        model.startList(for: serviceIdentifiers, kind: .password)
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.startList(for: serviceIdentifiers, kind: .oneTimeCode)
    }

    /// Never fills without the sheet: each fill needs the owner check.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        let identity = credentialRequest.credentialIdentity
        switch credentialRequest.type {
        case .password:
            model.startDirect(
                record: identity.recordIdentifier, serviceIdentifier: identity.serviceIdentifier, kind: .password)
        case .oneTimeCode:
            model.startDirect(
                record: identity.recordIdentifier, serviceIdentifier: identity.serviceIdentifier, kind: .oneTimeCode)
        default:
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
        }
    }

    override func prepareInterfaceForExtensionConfiguration() {
        model.startConfiguration()
    }

    // MARK: - The answer

    private func answer(_ outcome: AutoFillOutcome) {
        switch outcome {
        case .password(let credential):
            extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
        case .oneTimeCode(let credential):
            extensionContext.completeOneTimeCodeRequest(using: credential, completionHandler: nil)
        case .cancelled:
            extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
        case .configured:
            extensionContext.completeExtensionConfigurationRequest()
        }
    }
}
