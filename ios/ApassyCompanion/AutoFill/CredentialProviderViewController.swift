// The AutoFill extension of Apassy (ADR 0023). Placeholder until the extension is written.

import AuthenticationServices

final class CredentialProviderViewController: ASCredentialProviderViewController {
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
    }
}
