import SwiftUI

/// S3 while the link is registered (usually under 2 s): a small indicator is better than a blank
/// screen here (HIG, Loading, watchOS).
struct ConnectingView: View {
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 8) {
            ProgressView()
            Text("Connecting…")
                .font(.footnote)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Check the words")
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button("Cancel", role: .cancel, action: onCancel)
            }
        }
    }
}

#Preview {
    NavigationStack { ConnectingView {} }
}
