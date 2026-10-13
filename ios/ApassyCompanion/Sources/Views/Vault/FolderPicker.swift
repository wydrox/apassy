import ApassyVaultKit
import SwiftUI

/// A choice of a folder: "No folder" (the top level), then each folder in tree order, indented by
/// its level. The current place has a checkmark. Choosing calls `onPick` and closes the sheet; when
/// the move fails, the sheet stays open with the core's message (the alert of the tabs cannot show
/// above a sheet).
struct FolderPicker: View {
    let title: String
    /// The current folder; nil at the top level.
    let selected: String?
    /// The folders that can be chosen, in tree order (`FolderTree.choices` or `moveTargets`).
    let choices: [FolderChoice]
    /// The name of the top level: "No folder" for a credential, "Top level" for a folder.
    var topLabel = FolderTree.noFolder
    /// The move. Its failure goes to `VaultModel.report`, which `capturingAlert` hands to the sheet.
    let onPick: (String?) async -> Void
    @Environment(VaultModel.self) private var vault
    @Environment(\.dismiss) private var dismiss
    @State private var picking = false
    /// The message of a failed move.
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                if let error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
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
        .interactiveDismissDisabled(picking)
    }

    private func row(_ uuid: String?, name: String, level: Int, symbol: String) -> some View {
        Button {
            guard uuid != selected else {
                dismiss()
                return
            }
            picking = true
            error = nil
            Task {
                let failure = await vault.capturingAlert { await onPick(uuid) }
                picking = false
                if let failure {
                    error = failure
                } else {
                    dismiss()
                }
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
