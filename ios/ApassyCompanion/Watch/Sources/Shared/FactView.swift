import SwiftUI

/// A named fact of a request: the name small and secondary, the value under it. One VoiceOver
/// element, read in full.
struct FactView<Content: View>: View {
    let name: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(verbatim: name)
                .font(.caption)
                .foregroundStyle(.secondary)
            content
        }
        .accessibilityElement(children: .combine)
    }
}

extension FactView where Content == Text {
    /// A fact with one value, shown as it is (already escaped).
    init(name: String, value: String) {
        self.name = name
        self.content = Text(verbatim: value)
    }
}
