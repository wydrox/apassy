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

    func testNewLoginKeepsDraftUntilExplicitDiscard() throws {
        let app = launch(["-ApassyOpen", "vault"])
        let add = app.buttons["New Credential"]
        XCTAssertTrue(add.waitForExistence(timeout: 15))
        add.tap()
        let login = app.buttons["Login"]
        XCTAssertTrue(login.waitForExistence(timeout: 5))
        login.tap()

        let name = app.textFields["Name (required)"]
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        name.tap()
        let title = "Synthetic unsaved login"
        name.typeText(title)
        XCTAssertEqual(name.value as? String, title)
        app.buttons["Cancel"].tap()
        let confirmation = app.sheets["Discard changes?"]
        XCTAssertTrue(confirmation.waitForExistence(timeout: 5))
        let keep = confirmation.buttons["Keep Editing"]
        XCTAssertTrue(keep.waitForExistence(timeout: 5))
        XCTAssertTrue(confirmation.buttons["Discard Changes"].exists)
        keep.tap()
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        XCTAssertEqual(name.value as? String, title)

        app.buttons["Cancel"].tap()
        let discard = confirmation.buttons["Discard Changes"]
        XCTAssertTrue(discard.waitForExistence(timeout: 5))
        discard.tap()
        XCTAssertTrue(name.waitForNonExistence(timeout: 5))
        XCTAssertTrue(app.navigationBars["Personal"].waitForExistence(timeout: 5))

        add.tap()
        XCTAssertTrue(login.waitForExistence(timeout: 5))
        login.tap()
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        let emptyValue = try XCTUnwrap(name.value as? String)
        XCTAssertTrue(emptyValue.isEmpty || emptyValue == name.placeholderValue)
        app.buttons["Cancel"].tap()
        XCTAssertTrue(name.waitForNonExistence(timeout: 5))
    }

    func testNewLoginRetainsFolderAndCanBeFoundAfterSaving() {
        let app = launch(["-ApassyOpen", "folder:Billing"])
        XCTAssertTrue(app.navigationBars["Billing"].waitForExistence(timeout: 15))
        app.buttons["New Credential"].tap()
        // LabeledContent combines the visible label and the menu's accessible label.
        let inheritedFolder = app.buttons.matching(
            NSPredicate(format: "label BEGINSWITH %@ AND label CONTAINS %@", "Folder,", "Acme › Billing")
        ).firstMatch
        XCTAssertTrue(inheritedFolder.waitForExistence(timeout: 5))
        app.buttons["Login"].tap()

        let title = "Synthetic Billing account"
        let username = "billing-flow@example.invalid"
        enter(title, into: app.textFields["Name (required)"], in: app)
        enter(username, into: app.textFields["Username"], in: app)
        enter("Synthetic-only-password-47!", into: app.secureTextFields["Password"], in: app)
        app.buttons["Save"].tap()

        XCTAssertTrue(app.navigationBars[title].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts[username].waitForExistence(timeout: 5))
        let folder = app.buttons.matching(
            NSPredicate(format: "label CONTAINS %@ AND label CONTAINS %@", "Folder", "Acme › Billing")
        ).firstMatch
        for _ in 0..<4 where !folder.isHittable { app.swipeUp() }
        XCTAssertTrue(folder.exists, "The saved credential must retain its inherited Billing destination")

        app.tabBars.buttons["Search"].tap()
        let search = app.searchFields.firstMatch
        XCTAssertTrue(search.waitForExistence(timeout: 5))
        search.tap()
        search.typeText(username)
        let result = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", title))
        XCTAssertTrue(result.firstMatch.waitForExistence(timeout: 5))
        XCTAssertEqual(result.count, 1, "One Save must create one searchable credential")
        result.firstMatch.tap()
        XCTAssertTrue(app.navigationBars[title].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts[username].waitForExistence(timeout: 5))
    }

    private func enter(_ text: String, into field: XCUIElement, in app: XCUIApplication) {
        for _ in 0..<4 where !field.isHittable { app.swipeUp() }
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        XCTAssertTrue(field.isHittable)
        field.tap()
        field.typeText(text)
    }

    /// An iPhone with an iCloud vault and nothing connected: Agents says where the agents are and
    /// offers to connect, never "when the Mac is connected".
    func testAgentAccessSaysWhereTheAgentsAre() {
        let app = launch(["-ApassyOpen", "agents"])
        XCTAssertTrue(app.staticTexts["Agents run on your Mac"].waitForExistence(timeout: 15))
        XCTAssertFalse(app.staticTexts["Available when the Mac is connected"].exists)
        // The feed and connection state load independently; wait for the actionable state.
        XCTAssertTrue(app.buttons["Connect this iPhone"].waitForExistence(timeout: 10))
    }

    /// The search field belongs to the Search tab only; Vault and Decisions do not show one when
    /// pulled down.
    func testOnlyTheSearchTabHasTheSearchField() {
        let app = launch(["-ApassyOpen", "vault"])
        XCTAssertTrue(app.tabBars.buttons["Vault"].waitForExistence(timeout: 15))
        app.swipeDown()
        XCTAssertEqual(app.searchFields.count, 0, "Vault")
        app.tabBars.buttons["Requests"].tap()
        XCTAssertTrue(app.segmentedControls["requests.destination"].waitForExistence(timeout: 5))
        app.swipeDown()
        XCTAssertEqual(app.searchFields.count, 0, "Requests")
        XCTAssertFalse(app.tabBars.buttons["Agents"].exists)
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

    /// Requests offers the next useful action without empty Suggestions sections.
    func testRequestsWithoutConnectionOffersConnect() {
        let app = launch(["-ApassyOpen", "decisions"])
        XCTAssertTrue(app.segmentedControls["requests.destination"].waitForExistence(timeout: 15))
        XCTAssertTrue(app.buttons["Connect Mac"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["Suggestions"].exists)
        XCTAssertTrue(app.segmentedControls.buttons["History"].exists)
    }

    /// Fields remain useful without two unavailable Mac-only sections.
    func testCredentialLinksToAgentAccessWithoutMacOnlyPlaceholders() {
        let app = launch(["-ApassyOpen", "item:100"])
        XCTAssertTrue(app.navigationBars.firstMatch.waitForExistence(timeout: 15))
        let access = app.buttons["Agent Access"]
        for _ in 0..<4 where !access.isHittable { app.swipeUp() }
        XCTAssertTrue(access.exists)
        XCTAssertFalse(app.staticTexts["Agent use"].exists)
        XCTAssertFalse(app.staticTexts["Rules from your answers"].exists)
        access.tap()
        XCTAssertTrue(app.navigationBars["Agent Access"].waitForExistence(timeout: 5))
    }

    func testVaultRootShowsCredentialsAndOrganization() {
        let app = launch(["-ApassyOpen", "vault"])
        XCTAssertTrue(app.navigationBars["Personal"].waitForExistence(timeout: 15))
        let firstCredential = app.staticTexts["OpenAI"]
        XCTAssertTrue(firstCredential.waitForExistence(timeout: 5))
        XCTAssertTrue(firstCredential.isHittable, "The root must show a credential before scrolling")
        XCTAssertFalse(app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "Watchtower")).firstMatch.exists)
        let credential = app.staticTexts["Stripe live key"]
        for _ in 0..<4 where !credential.exists { app.swipeUp() }
        XCTAssertTrue(credential.exists)
        XCTAssertTrue(app.buttons["New Credential"].exists)
        app.buttons["Folders and tools"].tap()
        XCTAssertTrue(app.navigationBars["Folders and tools"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["Watchtower"].exists)
    }

    func testVaultTitleSelectorUsesTheNormalLockFlow() {
        let app = launch(["-ApassyOpen", "vault", "-ApassyPreviewDecisions", "locked"])
        let bar = app.navigationBars["Personal"]
        XCTAssertTrue(bar.waitForExistence(timeout: 15))
        let selector = bar.buttons["vault.selector"]
        XCTAssertTrue(selector.waitForExistence(timeout: 5))
        XCTAssertTrue(selector.isHittable)
        XCTAssertGreaterThanOrEqual(selector.frame.width, 28)
        XCTAssertGreaterThanOrEqual(selector.frame.height, 28)
        captureHeader(app, "compact-vault")
        // Check the actual native control edge. iOS constrains title menus to
        // 36 points here, within Apple's 28-point minimum (44 recommended).
        tapTitleEdge(selector, in: app, top: true)
        let family = app.buttons["vault.select.0a1b2c3d4e5f60718293a4b5c6d7e8f9"]
        XCTAssertTrue(family.waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["vault.select.4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c"].isEnabled)
        captureHeader(app, "compact-vault-selector")
        family.tap()
        let passphrase = app.secureTextFields["Passphrase"]
        XCTAssertTrue(passphrase.waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Family"].exists)
        XCTAssertFalse(app.tabBars.firstMatch.exists, "Credentials must stay behind the normal unlock screen")
        passphrase.tap()
        passphrase.typeText("preview passphrase\n")
        let selected = app.navigationBars["Family"]
        XCTAssertTrue(selected.waitForExistence(timeout: 10))
        XCTAssertLessThanOrEqual(selected.frame.height, 64)
        XCTAssertFalse(app.navigationBars["Personal"].exists)
    }

    func testCompactFolderFormAndSearchNavigation() {
        let app = launch(["-ApassyOpen", "folder:Billing"])
        let folderBar = app.navigationBars["Billing"]
        XCTAssertTrue(folderBar.waitForExistence(timeout: 15))
        XCTAssertLessThanOrEqual(folderBar.frame.height, 64)
        captureHeader(app, "compact-folder")
        app.buttons["New Credential"].tap()
        let formBar = app.navigationBars["New Credential"]
        XCTAssertTrue(formBar.waitForExistence(timeout: 5))
        XCTAssertLessThanOrEqual(formBar.frame.height, 64)
        captureHeader(app, "compact-form")
        app.buttons["Cancel"].tap()
        XCTAssertTrue(folderBar.waitForExistence(timeout: 5))
        app.tabBars.buttons["Search"].tap()
        let field = app.searchFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        XCTAssertFalse(app.navigationBars.staticTexts["Search"].exists)
        XCTAssertFalse(app.staticTexts["Search the vault"].exists)
        captureHeader(app, "compact-search-empty")
        field.tap()
        field.typeText("stripe")
        let item = app.staticTexts["Stripe live key"]
        XCTAssertTrue(item.waitForExistence(timeout: 5))
        captureHeader(app, "compact-search-results")
        item.tap()
        let detailBar = app.navigationBars["Stripe live key"]
        XCTAssertTrue(detailBar.waitForExistence(timeout: 5))
        XCTAssertLessThanOrEqual(detailBar.frame.height, 64)
        XCTAssertEqual(app.staticTexts.matching(identifier: "Stripe live key").count, 1,
                       "The credential title belongs in the navigation bar without a duplicate hero")
        captureHeader(app, "compact-credential-detail")
        detailBar.buttons.firstMatch.tap()
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        XCTAssertEqual(field.value as? String, "stripe")
    }

    func testVaultSelectorRemainsReachableAtAccessibilityTextSize() {
        let app = launch(["-ApassyOpen", "vault", "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"])
        let bar = app.navigationBars["Personal"]
        XCTAssertTrue(bar.waitForExistence(timeout: 15))
        let selector = bar.buttons["vault.selector"]
        XCTAssertTrue(selector.waitForExistence(timeout: 5))
        XCTAssertTrue(selector.isHittable)
        XCTAssertGreaterThanOrEqual(selector.frame.width, 28)
        XCTAssertGreaterThanOrEqual(selector.frame.height, 28)
        captureHeader(app, "compact-vault-accessibility")
        tapTitleEdge(selector, in: app, top: false)
        XCTAssertTrue(app.buttons["vault.select.4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["vault.addAnother"].exists)
    }

    private func tapTitleEdge(_ selector: XCUIElement, in app: XCUIApplication, top: Bool) {
        let frame = selector.frame
        app.coordinate(withNormalizedOffset: .zero)
            .withOffset(CGVector(dx: frame.midX, dy: top ? frame.minY + 1 : frame.maxY - 1)).tap()
    }

    private func captureHeader(_ app: XCUIApplication, _ name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    func testSettingsReachesAgentAccessAndRevocation() {
        let app = launch(["-ApassyOpen", "vault", "-ApassyPreviewAgents", "list"])
        XCTAssertTrue(app.buttons["Settings"].waitForExistence(timeout: 15))
        XCTAssertFalse(app.tabBars.buttons["Agents"].exists)
        app.buttons["Settings"].tap()
        app.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Agent Access")).firstMatch
            .tap()
        XCTAssertTrue(app.navigationBars["Agent Access"].waitForExistence(timeout: 5))
        let agent = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "8 uses this week"))
            .firstMatch
        for _ in 0..<4 where !agent.isHittable { app.swipeUp() }
        agent.tap()
        let remove = app.buttons["Remove Only: Deploy key"]
        XCTAssertTrue(remove.waitForExistence(timeout: 5))
        remove.tap()
        app.alerts.firstMatch.buttons["Remove"].tap()
        XCTAssertTrue(app.staticTexts["Removed on MacBook Pro."].waitForExistence(timeout: 10))
    }

    /// A vault whose questions are not open shows one row with Unlock; its passphrase opens its
    /// questions, and the vault on screen stays.
    func testLockedVaultOpensItsQuestions() {
        let app = launch(["-ApassyOpen", "decisions", "-ApassyPreviewDecisions", "locked"])
        XCTAssertTrue(app.segmentedControls["requests.destination"].waitForExistence(timeout: 15))
        let unlock = app.buttons["Unlock Family"]
        for _ in 0..<6 where !unlock.isHittable { app.swipeUp() }
        XCTAssertTrue(unlock.exists)
        XCTAssertTrue(app.staticTexts["Family is locked. Unlock to see its questions."].exists)
        let family = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", "Home router"))
        XCTAssertFalse(family.firstMatch.exists)
        unlock.tap()
        let field = app.secureTextFields["Passphrase"]
        XCTAssertTrue(field.waitForExistence(timeout: 5))
        field.tap()
        field.typeText("preview passphrase\n")
        XCTAssertTrue(field.waitForNonExistence(timeout: 10))
        for _ in 0..<6 where !family.firstMatch.isHittable { app.swipeDown() }
        XCTAssertTrue(family.firstMatch.exists)
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
        XCTAssertTrue(app.staticTexts["Sees"].exists)
        XCTAssertTrue(app.staticTexts["Exceptions"].exists)
        let exception = app.staticTexts["Always ask: Production Postgres"]
        for _ in 0..<6 where !exception.isHittable { app.swipeUp() }
        XCTAssertTrue(exception.exists)
        XCTAssertTrue(app.buttons["Remove Always ask: Production Postgres"].exists)
        for _ in 0..<5 where !app.staticTexts["Deploys only from the main branch."].isHittable {
            app.swipeUp()
        }
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
