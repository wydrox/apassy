import ApassyVaultKit
import Foundation
import Synchronization
import WatchConnectivity

/// Takes the Connect code from the iPhone (ADR 0039 section 6): `sendMessage` with
/// `[WatchHandoff.linkKey: <link>]` while this app is in the foreground. The reply is
/// `[okKey: true]` when the watch took the link, else `[errorKey: <a sentence>]`.
///
/// It also tells the iPhone the connection of this watch (`WatchConnectionReport`, the application
/// context) for Settings › Devices › Apple Watch.
///
/// WatchConnectivity calls the delegate on a queue of its own; the model runs on the main actor.
final class WatchLinkReceiver: NSObject, WCSessionDelegate, Sendable {
    typealias Handler = @Sendable (String) async -> String?

    private let handler: Handler
    /// The last connection to tell the iPhone; sent again when the session activates.
    private let report = Mutex<WatchConnectionReport?>(nil)

    init(handler: @escaping Handler) {
        self.handler = handler
        super.init()
    }

    /// Set this object as the delegate (WatchConnectivity holds it weakly) and activate.
    @MainActor
    func activate() {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        guard session.delegate !== self else { return }
        session.delegate = self
        session.activate()
    }

    /// Tell the iPhone the connection of this watch: at once when the session is active, else
    /// when it activates. Only the last one counts.
    @MainActor
    func publish(_ report: WatchConnectionReport?) {
        guard let report else { return }
        self.report.withLock { $0 = report }
        sendReport()
    }

    private func sendReport() {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        guard session.activationState == .activated, let report = report.withLock({ $0 }) else { return }
        try? session.updateApplicationContext(report.context)
    }

    func session(
        _ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: (any Error)?
    ) {
        sendReport()
    }

    func session(
        _ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void
    ) {
        let reply = Reply(send: replyHandler)
        guard let link = message[WatchHandoff.linkKey] as? String else {
            reply.send([WatchHandoff.errorKey: "Update Apassy on your iPhone and on this watch."])
            return
        }
        let handler = handler
        Task {
            if let problem = await handler(link) {
                reply.send([WatchHandoff.errorKey: problem])
            } else {
                reply.send([WatchHandoff.okKey: true])
            }
        }
    }

    /// The reply block of WatchConnectivity, called once from the task that handled the message.
    private struct Reply: @unchecked Sendable {
        let send: ([String: Any]) -> Void
    }
}
