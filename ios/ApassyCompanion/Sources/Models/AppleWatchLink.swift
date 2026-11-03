import Foundation
import Observation
import WatchConnectivity

/// The paired Apple Watch, for Settings > Devices > Add Apple Watch (ADR 0039 section 6): whether a
/// watch with Apassy is paired and reachable, and the handoff of a Connect code to it.
///
/// The iPhone only passes the code on. It never uses the link and never keeps it.
@MainActor @Observable
final class AppleWatchLink {
    /// What the watch said about a Connect code.
    enum SendResult: Equatable, Sendable {
        /// The watch took it and shows the words.
        case sent
        /// The watch refused it, with its sentence.
        case refused(String)
        /// The message did not reach the watch.
        case failed
    }

    static let shared = AppleWatchLink()

    private(set) var isPaired = false
    private(set) var isWatchAppInstalled = false
    private(set) var isReachable = false

    /// An Apple Watch is paired with this iPhone: Add Apple Watch shows. Without Apassy on the
    /// watch, the page says how to install it and keeps the scan off.
    var canAddWatch: Bool { WCSession.isSupported() && isPaired }

    @ObservationIgnored private let delegate = WatchSessionDelegate { state in
        Task { @MainActor in AppleWatchLink.shared.apply(state) }
    }

    private init() {}

    /// Activate the session once; later calls read its state again.
    func activate() {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        if session.delegate !== delegate {
            session.delegate = delegate
        }
        if session.activationState == .activated {
            apply(WatchSessionDelegate.State(session))
        } else {
            session.activate()
        }
    }

    private func apply(_ state: WatchSessionDelegate.State) {
        isPaired = state.paired
        isWatchAppInstalled = state.installed
        isReachable = state.reachable
    }

    /// Send the Connect code to Apassy on the watch, which must be open.
    func send(link: String) async -> SendResult {
        await WatchSessionDelegate.send(link)
    }
}
