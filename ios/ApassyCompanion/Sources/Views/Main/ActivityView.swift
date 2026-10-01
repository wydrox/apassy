import ApassyCompanionKit
import SwiftUI

/// The newest 50 entries of the activity log of the Mac.
struct ActivityView: View {
    let session: SessionModel

    var body: some View {
        NavigationStack {
            Group {
                if session.showsConnectionScreen(rows: session.activity.count) {
                    ConnectionUnavailableView(session: session)
                } else if session.activity.isEmpty {
                    ContentUnavailableView(
                        "No activity yet", systemImage: "clock",
                        description: Text("Decisions of the bouncer and of you show here."))
                } else {
                    List(session.activity) { entry in
                        ActivityRow(entry: entry)
                    }
                    .scrollEdgeEffectStyle(.soft, for: .top)
                    .refreshable { await session.refresh() }
                }
            }
            .navigationTitle("Activity")
            .connectionCapsule(session)
        }
    }
}

/// One entry: the decision, the agent, what it did, why, and when.
struct ActivityRow: View {
    let entry: ActivityEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                DecisionBadge(decision: entry.decision)
                Spacer(minLength: 8)
                Text(Date(timeIntervalSince1970: TimeInterval(entry.at)), format: .relative(presentation: .named))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(entry.agent)
                .font(.subheadline.weight(.semibold))
            if !entry.summary.isEmpty {
                Text(entry.summary)
                    .font(.system(.callout, design: .monospaced))
                    .lineLimit(3)
            }
            if !entry.reason.isEmpty {
                Text(entry.reason)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

/// Allowed, denied, or an error. The word and the symbol carry the meaning, not only the color.
struct DecisionBadge: View {
    let decision: String

    var body: some View {
        Label {
            Text(title)
        } icon: {
            Image(systemName: symbol)
                .foregroundStyle(tint)
        }
        .font(.caption.weight(.semibold))
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(.quaternary, in: .capsule)
    }

    private var title: String {
        switch decision {
        case "allow": "Allowed"
        case "deny": "Denied"
        case "error": "Error"
        default: decision
        }
    }

    private var symbol: String {
        switch decision {
        case "allow": "checkmark.circle.fill"
        case "deny": "xmark.circle.fill"
        default: "exclamationmark.triangle.fill"
        }
    }

    private var tint: Color {
        switch decision {
        case "allow": .green
        case "deny": .red
        default: .orange
        }
    }
}

#if DEBUG
    #Preview("Activity") {
        ActivityView(session: .preview())
    }

    #Preview("No activity") {
        ActivityView(session: .preview(inbox: Inbox(runs: [], accessRequests: [], activity: [])))
    }
#endif
