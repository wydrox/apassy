import XCTest

/// The tabs of the vault, in the Simulator with the synthetic preview vault (the launch arguments
/// of ios/README.md; no real vault, Mac, or relay).
@MainActor
final class VaultTabsUITests: XCTestCase {
    private func launch(_ arguments: [String]) -> XCUIApplication {
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchArguments = ["-ApassyPreviewVault", "-ApassyPreviewUnlocked"] + arguments
        app.launch()
        return app
    }

    /// An iPhone with an iCloud vault and nothing connected: Agents says where the agents are and
    /// offers to connect, never "when the Mac is connected".
    func testAgentsTabSaysWhereTheAgentsAre() {
        let app = launch(["-ApassyOpen", "agents"])
        XCTAssertTrue(app.staticTexts["Agents run on your Mac"].waitForExistence(timeout: 15))
        XCTAssertFalse(app.staticTexts["Available when the Mac is connected"].exists)
        XCTAssertTrue(app.buttons["Connect this iPhone"].exists)
    }

    /// The search field belongs to the Search tab only; Vault and Decisions do not show one when
    /// pulled down.
    func testOnlyTheSearchTabHasTheSearchField() {
        let app = launch(["-ApassyOpen", "vault"])
        XCTAssertTrue(app.tabBars.buttons["Vault"].waitForExistence(timeout: 15))
        app.swipeDown()
        XCTAssertEqual(app.searchFields.count, 0, "Vault")
        app.tabBars.buttons["Decisions"].tap()
        XCTAssertTrue(app.navigationBars["Decisions"].waitForExistence(timeout: 5))
        app.swipeDown()
        XCTAssertEqual(app.searchFields.count, 0, "Decisions")
        app.tabBars.buttons["Agents"].tap()
        XCTAssertTrue(app.navigationBars["Agents"].waitForExistence(timeout: 5))
        XCTAssertEqual(app.searchFields.count, 0, "Agents")
    }

    /// The Search tab still searches the vault.
    func testSearchTabFindsAnItem() {
        let app = launch(["-ApassyOpen", "search"])
        let field = app.searchFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 15))
        field.tap()
        field.typeText("stripe")
        XCTAssertTrue(app.staticTexts["Stripe live key"].waitForExistence(timeout: 5))
    }

    /// Decisions says where requests and suggestions are, never "when the Mac is connected", and
    /// offers the pairing on Wi-Fi that brings the requests.
    func testDecisionsSaysWhereRequestsAndSuggestionsAre() {
        let app = launch(["-ApassyOpen", "decisions"])
        XCTAssertTrue(app.navigationBars["Decisions"].waitForExistence(timeout: 15))
        let suggestions = app.staticTexts["Suggestions come from your Mac. They show in Apassy on the Mac."]
        for _ in 0..<3 where !suggestions.exists { app.swipeUp() }
        XCTAssertTrue(suggestions.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts.matching(Self.starts("Requests from agents show in Apassy on your Mac.")).firstMatch.exists)
        XCTAssertTrue(app.buttons["Pair with the Mac on Wi-Fi"].exists)
        XCTAssertFalse(app.staticTexts["Available when the Mac is connected"].exists)
    }

    /// A credential's Agent use and Rules say that they are on the Mac.
    func testCredentialSaysWhereAgentUseIs() {
        let app = launch(["-ApassyOpen", "item:100"])
        let agentUse = app.staticTexts.matching(Self.starts("Which agents used this credential is on your Mac.")).firstMatch
        let rules = app.staticTexts.matching(Self.starts("The rules from your answers are kept on your Mac.")).firstMatch
        XCTAssertTrue(app.navigationBars.firstMatch.waitForExistence(timeout: 15))
        for _ in 0..<4 where !agentUse.exists { app.swipeUp() }
        XCTAssertTrue(agentUse.waitForExistence(timeout: 5))
        // The list loads the rows below as they scroll in.
        for _ in 0..<3 where !rules.exists { app.swipeUp() }
        XCTAssertTrue(rules.waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["Available when the Mac is connected"].exists)
    }

    /// A vault whose questions are not open shows one row with Unlock; its passphrase opens its
    /// questions, and the vault on screen stays.
    func testLockedVaultOpensItsQuestions() {
        let app = launch(["-ApassyOpen", "decisions", "-ApassyPreviewDecisions", "locked"])
        let unlock = app.buttons["Unlock Family"]
        XCTAssertTrue(unlock.waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts["Family is locked. Unlock to see its questions."].exists)
        let family = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", "Home router"))
        XCTAssertFalse(family.firstMatch.exists)
        unlock.tap()
        let field = app.secureTextFields["Passphrase"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap()
        field.typeText("preview passphrase\n")
        XCTAssertTrue(family.firstMatch.waitForExistence(timeout: 10))
        XCTAssertFalse(app.buttons["Unlock Family"].exists)
    }

    private static func starts(_ text: String) -> NSPredicate {
        NSPredicate(format: "label BEGINSWITH %@", text)
    }
}
