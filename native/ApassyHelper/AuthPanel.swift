// Shared by the signed helper and the screenshot-only preview. No policy is
// evaluated by the panel itself: callers start it only after the view is visible.
import AppKit
import CoreGraphics
import LocalAuthentication
import os.log
#if canImport(LocalAuthenticationEmbeddedUI)
import LocalAuthenticationEmbeddedUI
#endif

private let panelLog = OSLog(subsystem: "com.wydrox.apassy", category: "touch-id-panel")
func logAuthPanelFallback(_ reason: String) {
    os_log("Using system Touch ID dialog: %{public}@", log: panelLog, type: .info, reason)
}

enum AuthPanelOutcome {
    case success, cancelled, fallback
    case failure(Error?)
}

// Check before constructing NSApplication: a command-line/headless session must
// retain the old LAContext path, rather than trying to connect AppKit to a server.
func prepareAuthPanelApplication() -> Bool {
    precondition(Thread.isMainThread)
    guard let session = CGSessionCopyCurrentDictionary() as? [String: Any],
          session[kCGSessionOnConsoleKey as String] as? Bool == true,
          session[kCGSessionLoginDoneKey as String] as? Bool == true else {
        logAuthPanelFallback("no GUI login session")
        return false
    }
    let app = NSApplication.shared
    guard app.setActivationPolicy(.accessory) else {
        logAuthPanelFallback("accessory application setup failed")
        return false
    }
    return true
}

func apassyPanelIcon() -> NSImage? {
    // Resolve from the executable too: Bundle.main's choice for an auxiliary
    // executable inside MacOS must not be a prerequisite for finding the icon.
    var candidates = [Bundle.main.bundleURL]
    if let executable = Bundle.main.executableURL { candidates.append(executable) }
    for candidate in candidates {
        var ancestor = candidate
        while ancestor.path != "/" {
            if ancestor.pathExtension == "app", ancestor.lastPathComponent == "Apassy.app",
               let icon = NSImage(contentsOf: ancestor.appendingPathComponent("Contents/Resources/AppIcon.icns")) {
                return icon
            }
            ancestor.deleteLastPathComponent()
        }
    }
    // Screenshot preview is unbundled; it supplies the repository icon explicitly.
    if let path = ProcessInfo.processInfo.environment["APASSY_PANEL_PREVIEW_ICON"] {
        return NSImage(contentsOfFile: path)
    }
    return nil
}

#if canImport(LocalAuthenticationEmbeddedUI)
@available(macOS 12.0, *)
final class AuthPanel: NSPanel {
    var outcome: AuthPanelOutcome?
    private let context: LAContext
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    init(context: LAContext, title: String, reason: String) {
        self.context = context
        super.init(contentRect: NSRect(x: 0, y: 0, width: 340, height: 360),
                   styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        isReleasedWhenClosed = false
        level = .floating
        hidesOnDeactivate = false
        isOpaque = false
        backgroundColor = .clear
        hasShadow = true
        let content = NSView()
        content.wantsLayer = true
        content.layer?.cornerRadius = 16
        content.layer?.masksToBounds = true
        contentView = content
        // A semantic AppKit background updates with the effective appearance.
        let background = NSVisualEffectView()
        background.material = .windowBackground
        background.blendingMode = .withinWindow
        background.state = .active
        background.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(background)
        NSLayoutConstraint.activate([
            background.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            background.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            background.topAnchor.constraint(equalTo: content.topAnchor),
            background.bottomAnchor.constraint(equalTo: content.bottomAnchor),
        ])
        let icon = NSImageView()
        icon.image = apassyPanelIcon()
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.setAccessibilityLabel("Apassy")
        icon.widthAnchor.constraint(equalToConstant: 64).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 64).isActive = true
        let heading = NSTextField(wrappingLabelWithString: title)
        heading.font = .systemFont(ofSize: 17, weight: .semibold)
        heading.alignment = .center
        let detail = NSTextField(wrappingLabelWithString: reason)
        detail.font = .systemFont(ofSize: 13)
        detail.textColor = .secondaryLabelColor
        detail.alignment = .center
        detail.maximumNumberOfLines = 3
        detail.lineBreakMode = .byTruncatingTail
        let authentication = LAAuthenticationView(context: context, controlSize: .large)
        let hint = NSTextField(labelWithString: "Touch the Touch ID sensor")
        hint.font = .systemFont(ofSize: 11)
        hint.textColor = .tertiaryLabelColor
        let fallback = NSButton(title: "Use Passphrase", target: self, action: #selector(usePassphrase))
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelPanel))
        cancel.keyEquivalent = "\u{1b}"
        fallback.keyEquivalent = ""
        let buttons = NSStackView(views: [fallback, cancel])
        buttons.orientation = .horizontal
        buttons.spacing = 12
        let stack = NSStackView(views: [icon, heading, detail, authentication, hint, buttons])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -24),
            heading.widthAnchor.constraint(equalTo: stack.widthAnchor),
            detail.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
        content.layoutSubtreeIfNeeded()
        setContentSize(NSSize(width: 340, height: stack.fittingSize.height + 48))
        defaultButtonCell = nil // Return must never authorize or select a fallback.
    }

    required init?(coder: NSCoder) { return nil }

    func showPanel(animated: Bool = true) -> Bool {
        let mouse = NSEvent.mouseLocation
        guard let screen = NSScreen.screens.first(where: { NSMouseInRect(mouse, $0.frame, false) }) ?? NSScreen.main else { return false }
        let visible = screen.visibleFrame
        setFrameOrigin(NSPoint(x: visible.midX - frame.width / 2,
                               y: visible.maxY - visible.height / 3 - frame.height / 2))
        alphaValue = animated ? 0 : 1
        orderFrontRegardless()
        makeKey()
        contentView?.layoutSubtreeIfNeeded()
        displayIfNeeded()
        if animated {
            NSAnimationContext.runAnimationGroup { animation in
                animation.duration = 0.12
                animator().alphaValue = 1
            }
        }
        return isVisible
    }

    func finish(_ result: AuthPanelOutcome) {
        guard outcome == nil else { return }
        outcome = result
        orderOut(nil)
        close()
        NSApplication.shared.stop(nil)
        // Wake NSApplication.run even when completion arrived from a dispatch block.
        if let wake = NSEvent.otherEvent(with: .applicationDefined, location: .zero,
            modifierFlags: [], timestamp: 0, windowNumber: 0, context: nil,
            subtype: 0, data1: 0, data2: 0) {
            NSApplication.shared.postEvent(wake, atStart: true)
        }
    }
    @objc private func cancelPanel() { finish(.cancelled); context.invalidate() }
    @objc private func usePassphrase() { finish(.fallback); context.invalidate() }
    override func cancelOperation(_ sender: Any?) { cancelPanel() }
}
#endif

/// Nil means UI is unavailable: callers must use their original system path.
/// The nested event loop keeps AppKit responsive while the sequential handler waits.
func evaluateInAuthPanel(context: LAContext, title: String, reason: String,
                         evaluate: @escaping (@escaping @Sendable (Bool, Error?) -> Void) -> Void) -> AuthPanelOutcome? {
    precondition(Thread.isMainThread)
    #if canImport(LocalAuthenticationEmbeddedUI)
    if #available(macOS 12.0, *) {
        guard prepareAuthPanelApplication() else { return nil }
        let panel = AuthPanel(context: context, title: title, reason: reason)
        guard panel.showPanel() else {
            panel.close()
            logAuthPanelFallback("panel could not become visible")
            return nil
        }
        // The view is attached to a visible window before evaluation starts.
        DispatchQueue.main.async {
            guard panel.outcome == nil else { return }
            evaluate { success, error in
                DispatchQueue.main.async { panel.finish(success ? .success : .failure(error)) }
            }
        }
        NSApplication.shared.run()
        if case .failure(let error)? = panel.outcome,
           let error = error as NSError?, error.domain == LAError.errorDomain,
           [LAError.Code.notInteractive.rawValue, LAError.Code.invalidContext.rawValue].contains(error.code) {
            logAuthPanelFallback("embedded authentication context unavailable")
            return nil
        }
        guard let outcome = panel.outcome else {
            panel.close()
            logAuthPanelFallback("application event loop ended before authentication")
            return nil
        }
        return outcome
    }
    #endif
    logAuthPanelFallback("embedded authentication framework unavailable")
    return nil
}
