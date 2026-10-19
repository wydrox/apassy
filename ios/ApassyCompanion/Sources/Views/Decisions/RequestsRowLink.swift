import SwiftUI

/// Keep the native disclosure and the same hit area in Waiting and History.
struct RequestsRowLink<Content: View>: View {
    let route: DecisionRoute
    @ViewBuilder let content: () -> Content

    var body: some View {
        NavigationLink(value: route) {
            content()
                .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                .contentShape(.rect)
        }
        .buttonStyle(.plain)
    }
}
