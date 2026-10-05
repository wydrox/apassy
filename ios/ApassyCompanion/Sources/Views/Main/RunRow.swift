import ApassyCompanionKit
import SwiftUI

/// The variable names of a run as small capsules. Names only: a value never reaches the phone.
struct VariableCapsules: View {
    let names: [String]

    var body: some View {
        FlowLayout(spacing: 6) {
            ForEach(Array(names.enumerated()), id: \.offset) { _, name in
                Text(name)
                    .font(.system(.caption, design: .monospaced))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(.quaternary, in: .capsule)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Variables: \(names.joined(separator: ", "))")
    }
}

/// The time that a run has left, as a bar and as text. It counts down each second.
struct TimeLeftView: View {
    let run: PendingRun
    let timeout: Int
    let fetchedAt: Date?

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            if let fetchedAt,
                let left = WaitClock.secondsLeft(
                    waitingSeconds: run.waitingSeconds, timeoutSeconds: timeout, fetchedAt: fetchedAt,
                    now: context.date)
            {
                let text = left == 0 ? "Time is up" : "\(WaitClock.text(left)) left"
                VStack(alignment: .leading, spacing: 4) {
                    ProgressView(value: Double(left), total: Double(max(timeout, 1)))
                        .tint(left <= 30 ? .orange : .accentColor)
                    Text(text)
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(left == 0 ? "Time is up" : "\(left) seconds left")
            }
        }
    }
}

/// A run that waits, as one row of the inbox.
struct RunRow: View {
    let run: PendingRun
    let timeout: Int
    let fetchedAt: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: "terminal")
                    .accessibilityHidden(true)
                Text(run.agent)
                    .font(.subheadline.weight(.semibold))
                Spacer(minLength: 0)
                Image(systemName: "chevron.right")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
            Text(CommandDisplay.line(run.command))
                .font(.system(.callout, design: .monospaced))
                .lineLimit(3)
            if let folder = CommandDisplay.folderTail(run.cwd) {
                Label(folder, systemImage: "folder")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            if !run.envNames.isEmpty {
                VariableCapsules(names: run.envNames)
            }
            if !run.risk.isEmpty {
                Label {
                    Text(run.risk)
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
            TimeLeftView(run: run, timeout: timeout, fetchedAt: fetchedAt)
        }
        .padding(.vertical, 4)
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
        .accessibilityHint("Opens the run")
    }
}

/// An agent asks for access to an item. The phone can only deny it.
struct AccessRequestRow: View {
    let request: AccessRequest
    let isDenying: Bool
    let deny: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("\(request.agent) asks for access")
                .font(.subheadline.weight(.semibold))
            Label(request.itemName, systemImage: "key")
                .font(.body)
            if !request.reason.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Text("The agent says:")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("\u{201C}\(request.reason)\u{201D}")
                        .font(.callout.italic())
                        .lineLimit(4)
                }
            }
            if let folder = CommandDisplay.folderTail(request.cwd) {
                Label(folder, systemImage: "folder")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            HStack {
                Button(role: .destructive, action: deny) {
                    if isDenying {
                        ProgressView()
                    } else {
                        Text("Deny")
                    }
                }
                .buttonStyle(.bordered)
                .disabled(isDenying)
            }
            Label("Give access in Apassy on your Mac", systemImage: "desktopcomputer")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
    }
}

#if DEBUG
    #Preview("Runs") {
        List {
            RunRow(run: PreviewData.migrateRun, timeout: 120, fetchedAt: Date())
            RunRow(run: PreviewData.quotedRun, timeout: 120, fetchedAt: Date().addingTimeInterval(-95))
            AccessRequestRow(request: PreviewData.accessRequest, isDenying: false) {}
        }
    }
#endif
