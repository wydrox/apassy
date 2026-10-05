import SwiftUI

/// "Forget this Mac", with its confirmation. It deletes the pairing on this iPhone only. It is on
/// the Mac tab and on the screen that says that another device answers, so the owner can act on
/// what that screen tells.
struct ForgetMacButton: View {
    let session: SessionModel
    @State private var confirming = false

    var body: some View {
        Button("Forget this Mac", role: .destructive) {
            confirming = true
        }
        .disabled(session.isEnding)
        .confirmationDialog("Forget this Mac?", isPresented: $confirming, titleVisibility: .visible) {
            Button("Forget this Mac", role: .destructive) {
                session.forgetMac()
            }
        } message: {
            Text("This iPhone deletes its pairing and its keys. The Mac is not asked. You pair again with a new code.")
        }
    }
}
