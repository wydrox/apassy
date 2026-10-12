import SwiftUI

/// The round tile of an agent: its first letter on its color, as in the mockup.
struct AgentAvatar: View {
    /// The name as the owner knows it (`AgentName.display`).
    let agent: String
    var large = false

    private static let known: [String: Color] = [
        "Claude Code": Color(red: 0.85, green: 0.47, blue: 0.34),
        "Codex": Color(red: 0.06, green: 0.64, blue: 0.50),
        "T3 Code": Color(red: 0.43, green: 0.35, blue: 0.90),
    ]
    private static let palette: [Color] = [.indigo, .teal, .orange, .pink, .brown, .cyan]

    private var color: Color {
        if let color = Self.known[agent] { return color }
        let sum = agent.unicodeScalars.reduce(0) { $0 + Int($1.value) }
        return Self.palette[sum % Self.palette.count]
    }

    var body: some View {
        let side: CGFloat = large ? 72 : 38
        Text(agent.first.map { String($0).uppercased() } ?? "?")
            .font(.system(size: side * 0.42, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: side, height: side)
            .background(color, in: .circle)
            .accessibilityHidden(true)
    }
}

/// The top of a decision: the agent, the question in one sentence, the project and the time left.
struct DecisionHeader: View {
    let agent: String
    let sentence: String
    let detail: String?
    /// When the answer is too late; nil hides the timer.
    let deadline: Date?

    var body: some View {
        VStack(spacing: 8) {
            AgentAvatar(agent: agent, large: true)
            Text(sentence)
                .font(.title2.bold())
                .multilineTextAlignment(.center)
            if detail != nil || deadline != nil {
                HStack(spacing: 4) {
                    if let detail { Text(detail) }
                    if detail != nil, deadline != nil { Text("·") }
                    if let deadline {
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            Text("\(Decisions.clock(Decisions.secondsLeft(until: deadline, now: context.date))) left")
                                .monospacedDigit()
                                .foregroundStyle(.orange)
                        }
                    }
                }
                .font(.subheadline)
                .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }
}

/// A small tag: "Production" in red, or a quiet one.
struct DecisionTag: View {
    let text: String
    var tint: Color?

    var body: some View {
        Text(text)
            .font(.caption.bold())
            .foregroundStyle(tint ?? .secondary)
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .background((tint ?? .secondary).opacity(0.12), in: .rect(cornerRadius: 7))
    }
}

/// A command in a gray box, in the monospaced font, as `CommandDisplay` writes it.
struct DecisionCommand: View {
    let line: String

    var body: some View {
        Text(line)
            .font(.callout.monospaced())
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(.fill.tertiary, in: .rect(cornerRadius: 12))
    }
}

/// The fixed glass bar at the bottom of a decision (mockup screen 6): the main answer, then Deny
/// and Allow Once, then a note.
struct DecisionBar<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(spacing: 8) { content }
            .controlSize(.large)
            .buttonBorderShape(.capsule)
            .padding(12)
            .glassEffect(.regular, in: .rect(cornerRadius: 32))
            .padding(.horizontal, 12)
            .padding(.bottom, 4)
    }
}

/// The place of the bar once the owner cannot answer: how the decision ended.
struct DecisionOutcomeBar: View {
    let outcome: QuestionOutcome

    private var symbol: String {
        switch outcome.tone {
        case .allowed: "checkmark.circle.fill"
        case .denied: "xmark.circle.fill"
        case .neutral: "clock"
        }
    }

    private var tint: Color {
        switch outcome.tone {
        case .allowed: .green
        case .denied: .red
        case .neutral: .clear
        }
    }

    var body: some View {
        Label(outcome.text, systemImage: symbol)
            .font(.headline)
            .multilineTextAlignment(.center)
            .padding(.horizontal, 24)
            .padding(.vertical, 14)
            .frame(maxWidth: .infinity)
            .glassEffect(.regular.tint(tint.opacity(0.3)), in: .rect(cornerRadius: 32))
            .padding(.horizontal, 12)
            .padding(.bottom, 4)
    }
}

extension View {
    /// The look of a button of the bar: `.primary` filled, `.deny` red, `.secondary` gray.
    func decisionButton(_ role: DecisionButtonRole) -> some View {
        buttonStyle(DecisionButtonStyle(role: role))
    }
}

enum DecisionButtonRole {
    case primary
    case deny
    case secondary
}

/// A capsule of 50 pt with its own fill, so it shows on the glass of the bar as in the mockup:
/// the accent with white text, a light red with red text, or a light gray with the accent text.
private struct DecisionButtonStyle: ButtonStyle {
    let role: DecisionButtonRole
    @Environment(\.isEnabled) private var isEnabled
    @ScaledMetric(relativeTo: .body) private var height: CGFloat = 50

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .lineLimit(1)
            .minimumScaleFactor(0.8)
            .foregroundStyle(foreground)
            .padding(.horizontal, 16)
            .frame(maxWidth: .infinity, minHeight: height)
            .background(background, in: .capsule)
            .contentShape(.capsule)
            .opacity(isEnabled ? (configuration.isPressed ? 0.7 : 1) : 0.4)
    }

    private var foreground: Color {
        switch role {
        case .primary: .white
        case .deny: .red
        case .secondary: .accentColor
        }
    }

    private var background: Color {
        switch role {
        case .primary: .accentColor
        case .deny: .red.opacity(0.12)
        case .secondary: Color(.tertiarySystemFill)
        }
    }
}
