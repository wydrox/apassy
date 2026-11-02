#!/bin/bash
# Screenshot only: no caller checks, keychain access, or policy evaluation.
set -euo pipefail
if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo 'Usage: touch-id-panel-preview.sh OUT.png [title] [reason]' >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREVIEW_TMP="$(mktemp -d "${TMPDIR:-/tmp}/apassy-panel-preview.XXXXXX")"
trap 'rm -rf "$PREVIEW_TMP"' EXIT
cat > "$PREVIEW_TMP/main.swift" <<'SWIFT'
import AppKit
import LocalAuthentication

if #available(macOS 12.0, *) {
    guard prepareAuthPanelApplication() else { exit(1) }
    let title = CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : "Unlock Apassy"
    let reason = CommandLine.arguments.count > 3 ? CommandLine.arguments[3] : "unlock the Apassy vault"
    let context = LAContext() // Intentionally never evaluated.
    let panel = AuthPanel(context: context, title: title, reason: reason)
    guard panel.showPanel(animated: false) else { exit(1) }
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
        guard let view = panel.contentView,
              let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { exit(1) }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        guard let data = bitmap.representation(using: .png, properties: [:]) else { exit(1) }
        do { try data.write(to: URL(fileURLWithPath: CommandLine.arguments[1])) }
        catch { exit(1) }
        panel.close()
        exit(0)
    }
    NSApplication.shared.run()
} else {
    exit(1)
}
SWIFT
xcrun --sdk macosx swiftc -swift-version 5 -warnings-as-errors \
  -target arm64-apple-macos15.0 -framework AppKit -weak_framework LocalAuthenticationEmbeddedUI \
  "$ROOT/native/ApassyHelper/AuthPanel.swift" "$PREVIEW_TMP/main.swift" \
  -o "$PREVIEW_TMP/preview"
APASSY_PANEL_PREVIEW_ICON="$ROOT/packaging/AppIcon.icns" "$PREVIEW_TMP/preview" "$@"
