import ApassyVaultKit
import SwiftUI

/// S3: the six safety words, to compare with the Mac before it writes this watch into the vault.
/// The owner confirms on the Mac; Cancel is the way out here.
struct CheckWordsView: View {
    let words: [String]
    let onCancel: () -> Void
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text("Check the words")
                    .font(.headline)
                    .accessibilityAddTraits(.isHeader)
                wordList
                Text("Confirm them on your Mac. If they differ, cancel.")
                Label("Waiting for your Mac", systemImage: "laptopcomputer")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button("Cancel", role: .cancel, action: onCancel)
            }
        }
    }

    /// Two columns of three (1 to 3, then 4 to 6); one column at the accessibility sizes.
    @ViewBuilder
    private var wordList: some View {
        if dynamicTypeSize.isAccessibilitySize {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(words.indices, id: \.self) { index in word(index) }
            }
        } else {
            let rows = (words.count + 1) / 2
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 4) {
                ForEach(0..<rows, id: \.self) { row in
                    GridRow {
                        word(row)
                        if row + rows < words.count { word(row + rows) }
                    }
                }
            }
        }
    }

    private func word(_ index: Int) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 4) {
            Text(index + 1, format: .number)
                .monospacedDigit()
                .foregroundStyle(.secondary)
            Text(verbatim: words[index])
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(verbatim: "Word \(index + 1), \(words[index])"))
    }
}

#Preview {
    NavigationStack { CheckWordsView(words: PreviewWatchService.words) {} }
}
