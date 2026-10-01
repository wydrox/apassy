import SwiftUI

/// The connection to the Mac as a floating glass capsule. Selecting it asks again.
struct StatusCapsule: View {
    let state: SessionModel.ConnectionState
    let macName: String
    let retry: () -> Void

    var body: some View {
        Button(action: retry) {
            HStack(spacing: 8) {
                if state == .connecting {
                    ProgressView()
                } else {
                    Image(systemName: symbol)
                        .foregroundStyle(tint ?? .primary)
                }
                Text(title)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.primary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .glassEffect(.regular.tint(tint?.opacity(0.28)).interactive(), in: .capsule)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .accessibilityHint("Checks the connection again")
    }

    private var title: String {
        switch state {
        case .connecting: "Connecting to \(macName)"
        case .connected: "Connected to \(macName)"
        case .unreachable: "Mac not reachable"
        case .localNetworkDenied: "Allow local network access"
        case .pinMismatch: "Not the Mac you paired with"
        case .problem: "Problem with the Mac"
        }
    }

    private var symbol: String {
        switch state {
        case .connecting: "arrow.triangle.2.circlepath"
        case .connected: "checkmark.circle.fill"
        case .unreachable: "wifi.exclamationmark"
        case .localNetworkDenied: "network.slash"
        case .pinMismatch: "exclamationmark.shield.fill"
        case .problem: "exclamationmark.triangle.fill"
        }
    }

    /// The tint of the glass. The state is always in the words and the symbol too.
    private var tint: Color? {
        switch state {
        case .connecting: nil
        case .connected: .green
        case .unreachable, .localNetworkDenied, .problem: .orange
        case .pinMismatch: .red
        }
    }
}

extension View {
    /// The status capsule, floating at the top of a tab. Selecting it asks the Mac again.
    func connectionCapsule(_ session: SessionModel) -> some View {
        safeAreaInset(edge: .top, spacing: 0) {
            StatusCapsule(state: session.state, macName: session.macName) {
                Task { await session.refresh() }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
        }
    }
}

#if DEBUG
    #Preview("Connected") {
        StatusCapsule(state: .connected, macName: "Mac mini") {}
            .padding()
    }

    #Preview("Not reachable") {
        StatusCapsule(state: .unreachable, macName: "Mac mini") {}
            .padding()
    }

    #Preview("Local network") {
        StatusCapsule(state: .localNetworkDenied, macName: "Mac mini") {}
            .padding()
    }
#endif
