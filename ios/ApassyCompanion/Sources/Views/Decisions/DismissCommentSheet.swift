import ApassyVaultKit
import SwiftUI

/// The caller retains the exact displayed question snapshot through Send.
struct DismissCommentSheet: View {
    let send: (RemoteAnswer) -> Void
    @State private var comment = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                TextField("Comment to the agent", text: $comment)
                    .onChange(of: comment) { _, value in
                        comment = String(String.UnicodeScalarView(value.unicodeScalars.prefix(500)))
                    }
                Text("\(comment.unicodeScalars.count)/500 characters")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .navigationTitle("Dismiss with comment")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Send") {
                        send(RemoteAnswer(kind: .denyWithComment, comment: comment))
                        dismiss()
                    }
                }
            }
        }
        .presentationDetents([.medium])
    }
}
