import ApassyVaultKit
import Foundation
import Synchronization
import WatchConnectivity

/// The delegate of the WatchConnectivity session of the iPhone (`AppleWatchLink`). WatchConnectivity
/// calls it on a queue of its own, so it only reports the state.
final class WatchSessionDelegate: NSObject, WCSessionDelegate, Sendable {
    /// The state of the session, read on the queue of WatchConnectivity.
    struct State: Sendable {
        let paired: Bool
        let installed: Bool
        let reachable: Bool

        init(_ session: WCSession) {
            let activated = session.activationState == .activated
            paired = activated && session.isPaired
            installed = activated && session.isWatchAppInstalled
            reachable = activated && session.isReachable
        }
    }

    private let onChange: @Sendable (State) -> Void

    init(onChange: @escaping @Sendable (State) -> Void) {
        self.onChange = onChange
        super.init()
    }

    func session(
        _ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: (any Error)?
    ) {
        onChange(State(session))
    }

    func sessionDidBecomeInactive(_ session: WCSession) { onChange(State(session)) }

    func sessionDidDeactivate(_ session: WCSession) {
        // Another watch was selected: activate the session for it.
        session.activate()
    }

    func sessionWatchStateDidChange(_ session: WCSession) { onChange(State(session)) }

    func sessionReachabilityDidChange(_ session: WCSession) { onChange(State(session)) }

    /// One message with the link (`WatchHandoff`); the reply says whether the watch took it.
    static func send(_ link: String) async -> AppleWatchLink.SendResult {
        await withCheckedContinuation { (continuation: CheckedContinuation<AppleWatchLink.SendResult, Never>) in
            let once = ResumeOnce(continuation)
            WCSession.default.sendMessage(
                [WatchHandoff.linkKey: link],
                replyHandler: { @Sendable reply in
                    if reply[WatchHandoff.okKey] as? Bool == true {
                        once.resume(.sent)
                    } else {
                        once.resume(.refused(reply[WatchHandoff.errorKey] as? String ?? ""))
                    }
                },
                errorHandler: { @Sendable _ in once.resume(.failed) })
        }
    }

    /// Resumes the continuation once, whichever handler of WatchConnectivity comes.
    private final class ResumeOnce: Sendable {
        private let continuation: Mutex<CheckedContinuation<AppleWatchLink.SendResult, Never>?>

        init(_ continuation: CheckedContinuation<AppleWatchLink.SendResult, Never>) {
            self.continuation = Mutex(continuation)
        }

        func resume(_ result: AppleWatchLink.SendResult) {
            let pending = continuation.withLock { (value: inout CheckedContinuation<AppleWatchLink.SendResult, Never>?) in
                defer { value = nil }
                return value
            }
            pending?.resume(returning: result)
        }
    }
}
