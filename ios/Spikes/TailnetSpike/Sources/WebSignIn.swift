import AuthenticationServices
import UIKit

/// The sign-in of plan unit T4: the node's sign-in URL in an ASWebAuthenticationSession sheet.
/// Tailscale's login page does not call back into the app, so the model closes the sheet when the
/// node reaches Running.
final class WebSignIn: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var session: ASWebAuthenticationSession?

    @MainActor
    func start(_ url: URL, onEnd: @escaping (String) -> Void) {
        cancel()
        let session = ASWebAuthenticationSession(url: url, callback: .customScheme("apassy-tailnet-spike")) { _, error in
            onEnd(error.map { $0.localizedDescription } ?? "finished")
        }
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = false
        self.session = session
        if !session.start() { onEnd("the sheet did not start") }
    }

    @MainActor
    func cancel() {
        session?.cancel()
        session = nil
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            let windows = scenes.flatMap { $0.windows }
            if let window = windows.first(where: { $0.isKeyWindow }) ?? windows.first {
                return window
            }
            return UIWindow(windowScene: scenes[0])
        }
    }
}
