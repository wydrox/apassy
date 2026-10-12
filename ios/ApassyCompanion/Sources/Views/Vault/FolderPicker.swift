import ApassyVaultKit
import SwiftUI

/// A choice of a folder: "No folder" (the top level), then each folder in tree order, indented by
/// its level. The current place has a checkmark. Choosing calls `onPick` and closes the sheet.
struct FolderPicker: View {
    let title: String
    /// The current folder; nil at the top level.
    let selected: String?
    /// The folders that can be chosen, in tree order (`FolderTree.choices` or `moveTargets`).
    let choices: [FolderChoice]
    /// The name of the top level: "No folder" for a credential, "Top level" for a folder.
    var topLabel = FolderTree.noFolder
    let onPick: (String?) async -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var picking = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    row(nil, name: topLabel, level: 0, symbol: "tray")
                    ForEach(choices) { choice in
                        row(choice.folder.uuid, name: choice.folder.name, level: choice.level, symbol: "folder")
                    }
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(role: .cancel) { dismiss() }
                }
            }
            .disabled(picking)
        }
    }

    private func row(_ uuid: String?, name: String, level: Int, symbol: String) -> some View {
        Button {
            guard uuid != selected else {
                dismiss()
                return
            }
            picking = true
            Task {
                await onPick(uuid)
                dismiss()
            }
        } label: {
            HStack(spacing: 10) {
                Image(systemName: symbol)
                    .foregroundStyle(uuid == nil ? Color.secondary : Color.folderTile)
                    .accessibilityHidden(true)
                Text(name)
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Spacer(minLength: 4)
                if uuid == selected {
                    Image(systemName: "checkmark")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(.tint)
                        .accessibilityHidden(true)
                }
            }
            .padding(.leading, CGFloat(level) * 20)
            .contentShape(.rect)
        }
        .accessibilityAddTraits(uuid == selected ? .isSelected : [])
    }
}
