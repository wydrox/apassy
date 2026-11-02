import Testing
@testable import ApassyVaultKit

struct AutoFillAuthenticationIsolationTests {
    @Test func autoFillDefaultsHaveNoWindowProvider() {
        // These are AutoFill's actual constructors. No authentication or keychain read.
        #expect(!KeychainPassphraseStore().usesAppWindow)
        #expect(!BiometricOwnerCheck().usesAppWindow)
    }
}
