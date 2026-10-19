import SwiftUI

/// Both Requests destinations use the same native list surface and row geometry.
struct RequestsList<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        List {
            content()
                .listRowInsets(EdgeInsets(top: 12, leading: 16, bottom: 12, trailing: 16))
        }
        .listStyle(.insetGrouped)
        .listSectionSpacing(16)
        .contentMargins(.top, 16, for: .scrollContent)
        .scrollContentBackground(.visible)
    }
}
