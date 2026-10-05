/// The phase of the app, as `ScenePhase` says it, without SwiftUI so a test can use it.
enum AppPhase: Equatable {
    case active
    case inactive
    case background
}

/// When the app hides its content behind the privacy cover.
enum CoverPolicy {
    /// - Parameters:
    ///   - phase: The phase of the app.
    ///   - systemPromptDepth: How many system prompts of the app are up: its own Face ID prompt, or
    ///     the camera permission dialog. Such a prompt makes the scene inactive for a moment, and
    ///     the owner needs the screen behind it.
    ///
    /// The app switcher shows the app while it is inactive or in the background, so both cover. A
    /// prompt of the app excuses only the inactive phase: in the background the cover always shows.
    static func isCovered(phase: AppPhase, systemPromptDepth: Int) -> Bool {
        switch phase {
        case .active: false
        case .inactive: systemPromptDepth <= 0
        case .background: true
        }
    }

    /// Whether the app asks the Mac for the inbox. It stops in the background only: the short
    /// inactive moments (a prompt, the notification shade) do not end the polling.
    static func polls(in phase: AppPhase) -> Bool {
        phase != .background
    }
}
