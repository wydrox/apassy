import Foundation
import Testing

/// The AutoFill extension never sees a demo item: its target does not link `ApassyVaultDemo`, does
/// not compile the demo sources of the app, and no AutoFill source names the demo. The checks read
/// the XcodeGen spec and the sources of the repository.
@Suite struct AutoFillIsolationTests {
    /// `ios/ApassyCompanion`, from this file.
    private static let app = URL(filePath: #filePath)
        .deletingLastPathComponent()  // ApassyVaultDemoTests
        .deletingLastPathComponent()  // Tests
        .deletingLastPathComponent()  // ApassyVaultKit
        .deletingLastPathComponent()  // ios
        .appending(path: "ApassyCompanion")

    /// The lines of one target of `project.yml`: from `  <name>:` to the next target.
    private static func target(_ name: String) throws -> String {
        let spec = try String(contentsOf: app.appending(path: "project.yml"), encoding: .utf8)
        let lines = spec.components(separatedBy: "\n")
        guard let start = lines.firstIndex(of: "  \(name):") else {
            Issue.record("No target \(name) in project.yml")
            return ""
        }
        var end = start + 1
        // A target's own lines are indented by four spaces or more (or are empty); the next
        // target, or the next top-level key, ends it.
        while end < lines.count, lines[end].isEmpty || lines[end].hasPrefix("    ") || lines[end].hasPrefix("  #") {
            end += 1
        }
        return lines[start..<end].joined(separator: "\n")
    }

    @Test func theAutoFillTargetDoesNotLinkTheDemo() throws {
        let autofill = try Self.target("ApassyAutoFill")
        #expect(autofill.contains("product: ApassyVaultKit"))
        #expect(!autofill.contains("ApassyVaultDemo"))
        #expect(!autofill.contains("Sources/Demo"))
        #expect(!autofill.contains("- path: Sources"))
    }

    @Test func theAppAndTheWatchLinkTheDemo() throws {
        #expect(try Self.target("ApassyCompanion").contains("product: ApassyVaultDemo"))
        #expect(try Self.target("ApassyWatch").contains("product: ApassyVaultDemo"))
    }

    @Test func noAutoFillSourceNamesTheDemo() throws {
        let folder = Self.app.appending(path: "AutoFill")
        let files = try FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "swift" }
        #expect(!files.isEmpty)
        for file in files {
            let text = try String(contentsOf: file, encoding: .utf8)
            for name in ["ApassyVaultDemo", "DemoVault", "DemoSession", "DemoAppSession"] {
                #expect(!text.contains(name), "\(file.lastPathComponent) names \(name)")
            }
        }
    }
}
