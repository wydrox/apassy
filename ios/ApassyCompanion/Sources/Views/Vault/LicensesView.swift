import SwiftUI

/// The notices and license texts of the code and data in the app: the `licenses` folder of
/// the repository, copied into the app as it is into the Mac app.
struct LicensesView: View {
    private struct Entry: Identifiable, Hashable {
        let url: URL
        let title: String
        var id: URL { url }
    }

    private var entries: [Entry] {
        guard let root = Bundle.main.url(forResource: "licenses", withExtension: nil),
            let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey])
        else { return [] }
        let prefix = root.standardizedFileURL.path(percentEncoded: false)
        return files.compactMap { $0 as? URL }
            .filter { (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true }
            .map { url in
                var title = url.standardizedFileURL.path(percentEncoded: false)
                if title.hasPrefix(prefix) { title.removeFirst(prefix.count) }
                return Entry(url: url, title: title.trimmingCharacters(in: CharacterSet(charactersIn: "/")))
            }
            .sorted { lhs, rhs in
                // The notices first, then each component.
                if lhs.title.hasPrefix("THIRD-PARTY") != rhs.title.hasPrefix("THIRD-PARTY") {
                    return lhs.title.hasPrefix("THIRD-PARTY")
                }
                return lhs.title.localizedStandardCompare(rhs.title) == .orderedAscending
            }
    }

    var body: some View {
        List(entries) { entry in
            NavigationLink(entry.title) {
                ScrollView {
                    Text((try? String(contentsOf: entry.url, encoding: .utf8)) ?? "")
                        .font(.footnote.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
                .navigationTitle(entry.title)
                .navigationBarTitleDisplayMode(.inline)
            }
        }
        .overlay {
            if entries.isEmpty {
                ContentUnavailableView("No notices in this build", systemImage: "doc.text")
            }
        }
        .navigationTitle("Licenses")
    }
}
