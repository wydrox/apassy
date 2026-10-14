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

    /// With the synthetic feeds of two Macs and two vaults, Agents lists the agents by vault and
    /// Mac, and a row opens the agent's page with its use and its exceptions.
    func testAgentsListOpensAnAgent() {
        let app = launch(["-ApassyOpen", "agents", "-ApassyPreviewAgents", "list"])
        let row = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "54 uses this week")).firstMatch
        XCTAssertTrue(row.waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts["Personal · Mac mini"].exists)
        XCTAssertFalse(app.staticTexts["Agents run on your Mac"].exists)
        row.tap()
        XCTAssertTrue(app.navigationBars["Claude Code"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["On Mac mini · Personal"].exists)
        XCTAssertTrue(app.staticTexts["This week"].exists)
        let exception = app.staticTexts["Always ask: Production Postgres"]
        for _ in 0..<6 where !exception.isHittable { app.swipeUp() }
        XCTAssertTrue(exception.exists)
        XCTAssertTrue(app.buttons["Remove Always ask: Production Postgres"].exists)
        XCTAssertTrue(app.staticTexts["Deploys only from the main branch."].exists)
    }

    /// "Remove" asks first, naming the agent, the credential, and the Mac; an "only" item needs no
    /// Face ID, and the row says where it was removed.
    func testRemovingAnExceptionAsksFirst() {
        let app = launch(["-ApassyOpen", "agents", "-ApassyPreviewAgents", "list"])
        let row = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "8 uses this week")).firstMatch
        for _ in 0..<3 where !(row.waitForExistence(timeout: 5) && row.isHittable) { app.swipeUp() }
        row.tap()
        XCTAssertTrue(app.navigationBars["Claude Code"].waitForExistence(timeout: 5))
        let remove = app.buttons["Remove Only: Deploy key"]
        for _ in 0..<6 where !(remove.exists && remove.isHittable) { app.swipeUp() }
        remove.tap()
        let alert = app.alerts.firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 5))
        XCTAssertTrue(alert.label.contains("Claude Code"))
        XCTAssertTrue(alert.label.contains("Deploy key"))
        XCTAssertTrue(alert.label.contains("MacBook Pro"))
        alert.buttons["Remove"].tap()
        XCTAssertTrue(app.staticTexts["Removed on MacBook Pro."].waitForExistence(timeout: 10))
        XCTAssertFalse(app.buttons["Remove Only: Deploy key"].exists)
    }

    /// On a vault that is not selected, whose feed came after its keys were read, "Remove" shows
    /// when its passphrase is behind Face ID (the preview passphrase stands in): the tap reads the
    /// keys again, then asks as usual, and the Mac removes it.
    func testRemovingOnAnotherVaultReadsItsKeysFirst() {
        let app = launch(["-ApassyOpen", "agents", "-ApassyPreviewAgents", "othervault"])
        XCTAssertTrue(app.navigationBars["Claude Code"].waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts["On MacBook Pro · Work"].waitForExistence(timeout: 5))
        let remove = app.buttons["Remove Only: Deploy key"]
        for _ in 0..<6 where !(remove.exists && remove.isHittable) { app.swipeUp() }
        XCTAssertTrue(remove.exists)
        XCTAssertFalse(app.staticTexts["Select Work on this iPhone to remove exceptions of its agents."].exists)
        remove.tap()
        let alert = app.alerts.firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 10))
        XCTAssertTrue(alert.label.contains("Deploy key"))
        alert.buttons["Remove"].tap()
        XCTAssertTrue(app.staticTexts["Removed on MacBook Pro."].waitForExistence(timeout: 10))
    }

    /// A Mac that has not reported for days is dimmed and offers no removal.
    func testAStaleMacOffersNoRemoval() {
        let app = launch(["-ApassyOpen", "agents", "-ApassyPreviewAgents", "stale"])
        XCTAssertTrue(app.navigationBars["CI on GitHub"].waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts.matching(Self.starts("MacBook Pro has not reported since")).firstMatch.exists)
        let exception = app.staticTexts["Never: Stripe live key"]
        for _ in 0..<6 where !exception.isHittable { app.swipeUp() }
        XCTAssertTrue(exception.exists)
        XCTAssertFalse(app.buttons["Remove Never: Stripe live key"].exists)
    }

    /// "Sees" of an "only these items" agent lists the rows of its Mac and says that access granted
    /// on the Mac is not shown.
    func testSeesSaysWhatTheMacLists() {
        let app = launch(["-ApassyOpen", "agents", "-ApassyPreviewAgents", "restricted"])
        XCTAssertTrue(app.navigationBars["Claude Code"].waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts["On MacBook Pro · Work"].exists)
        let footer = app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS %@", "Listed for this agent on MacBook Pro.")
        ).firstMatch
        for _ in 0..<6 where !(footer.exists && footer.isHittable) { app.swipeUp() }
        XCTAssertTrue(footer.exists)
        XCTAssertTrue(footer.label.contains("Access granted on the Mac is not shown here."))
        XCTAssertFalse(app.staticTexts["No credential"].exists)
    }

    /// A settle that this iPhone cannot open is "not applied, or unknown", never "removed", and the
    /// row stays.
    func testAnUnopenableSettleIsNeverRemoved() {
        let app = launch([
            "-ApassyOpen", "agents", "-ApassyPreviewAgents", "unverified", "-ApassyPreviewAgentsScroll", "exceptions",
        ])
        XCTAssertTrue(app.navigationBars["Claude Code"].waitForExistence(timeout: 15))
        let line = app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS %@", "Not applied, or unknown. Check the list on MacBook Pro.")
        ).firstMatch
        XCTAssertTrue(line.waitForExistence(timeout: 10))
        XCTAssertFalse(app.staticTexts["Removed on MacBook Pro."].exists)
        XCTAssertTrue(app.buttons["Remove Only: Cloudflare API (not on this iPhone)"].exists)
    }

    private static func starts(_ text: String) -> NSPredicate {
        NSPredicate(format: "label BEGINSWITH %@", text)
    }
}
