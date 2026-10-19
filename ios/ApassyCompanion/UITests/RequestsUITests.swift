import XCTest

/// In-memory fixtures on a dedicated Simulator; this does not prove biometric or relay delivery.
@MainActor
final class RequestsUITests: XCTestCase {
    private func launch(_ arguments: [String] = []) -> XCUIApplication {
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchArguments = ["-ApassyPreviewVault", "-ApassyPreviewUnlocked", "-ApassyOpen", "decisions", "-ApassyPreviewDecisions", "list"] + arguments
        app.launch()
        XCTAssertTrue(app.segmentedControls["requests.destination"].waitForExistence(timeout: 15))
        return app
    }

    func testRoutineReadOffersOneTimeActionAndProductionRequiresReview() {
        let app = launch()
        let review = app.buttons["Review Stripe live"]
        XCTAssertTrue(review.waitForExistence(timeout: 10))
        XCTAssertFalse(app.buttons["Allow Stripe live once"].exists)
        let allow = app.buttons["Allow OpenAI API once"]
        for _ in 0..<4 where !allow.isHittable { app.swipeUp() }
        XCTAssertTrue(allow.isHittable)
        XCTAssertFalse(app.staticTexts["Suggestions"].exists)
        attach(app, "native-waiting")
        allow.tap()
        let sent = app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "Waiting for the Mac")).firstMatch
        XCTAssertTrue(sent.waitForExistence(timeout: 10))
        XCTAssertTrue(app.buttons["Done"].exists)
        XCTAssertFalse(app.buttons["Allow OpenAI API once"].exists)
        attach(app, "native-sent-unconfirmed")
    }

    func testHistorySearchReadOnlyDetailAndClear() {
        let app = launch()
        app.segmentedControls.buttons["History"].tap()
        let approved = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "GitHub read token")).firstMatch
        XCTAssertTrue(approved.waitForExistence(timeout: 10))
        attach(app, "native-history")
        approved.tap()
        XCTAssertTrue(app.navigationBars["Request history"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Allowed once"].exists)
        XCTAssertTrue(app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", "Execution")).firstMatch.exists)
        XCTAssertFalse(app.buttons["Allow Once"].exists)
        attach(app, "native-history-detail")
        app.navigationBars.buttons.firstMatch.tap()
        app.buttons["History options"].tap()
        app.buttons["Allowed"].tap()
        XCTAssertTrue(approved.exists)
        XCTAssertFalse(app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "Deploy token")).firstMatch.exists)
        app.buttons["History options"].tap()
        app.buttons["All"].tap()
        openHistorySearch(app)
        let search = app.searchFields.firstMatch
        XCTAssertTrue(search.waitForExistence(timeout: 5))
        search.tap()
        search.typeText("Deploy")
        let unknown = app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "Deploy token")).firstMatch
        XCTAssertTrue(unknown.waitForExistence(timeout: 5))
        XCTAssertFalse(approved.exists)
        unknown.tap()
        XCTAssertTrue(app.staticTexts["Not confirmed"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["Denied"].exists)
        attach(app, "native-history-unconfirmed")
        app.navigationBars.buttons.firstMatch.tap()
        app.buttons["Done"].tap()
        XCTAssertTrue(app.buttons["History options"].waitForExistence(timeout: 5))
        app.buttons["History options"].tap()
        app.buttons["Clear Personal History"].tap()
        let clear = app.buttons["Clear History"].firstMatch
        XCTAssertTrue(clear.waitForExistence(timeout: 5))
        clear.tap()
        XCTAssertTrue(unknown.waitForNonExistence(timeout: 5))
        XCTAssertFalse(approved.exists)
    }

    func testHistoryRetainsSearchWhenSwitchingDestinations() {
        let app = launch()
        app.segmentedControls.buttons["History"].tap()
        openHistorySearch(app)
        let search = app.searchFields.firstMatch
        XCTAssertTrue(search.waitForExistence(timeout: 5))
        search.tap()
        search.typeText("GitHub")
        app.buttons["Done"].tap()
        app.segmentedControls.buttons["Waiting"].tap()
        XCTAssertFalse(app.searchFields.firstMatch.exists)
        app.segmentedControls.buttons["History"].tap()
        openHistorySearch(app)
        XCTAssertEqual(app.searchFields.firstMatch.value as? String, "GitHub")
    }

    func testWaitingAndHistoryKeepTheSameNavigationLayout() {
        let app = launch()
        let picker = app.segmentedControls["requests.destination"]
        XCTAssertTrue(picker.waitForExistence(timeout: 5))
        let initialPicker = picker.frame
        let bar = app.navigationBars.firstMatch
        XCTAssertFalse(bar.staticTexts["Requests"].exists)
        XCTAssertLessThanOrEqual(bar.frame.height, 64, "The root navigation bar must stay compact")
        let initialBar = bar.frame
        attach(app, "compact-waiting")

        picker.buttons["History"].tap()
        XCTAssertTrue(app.buttons.matching(NSPredicate(format: "label CONTAINS %@", "GitHub read token")).firstMatch.waitForExistence(timeout: 5))
        XCTAssertFalse(app.searchFields.firstMatch.exists)
        XCTAssertEqual(picker.frame.minY, initialPicker.minY, accuracy: 1)
        XCTAssertEqual(picker.frame.minX, initialPicker.minX, accuracy: 1)
        XCTAssertEqual(picker.frame.width, initialPicker.width, accuracy: 1)
        XCTAssertFalse(bar.staticTexts["Requests"].exists)
        XCTAssertEqual(bar.frame.minY, initialBar.minY, accuracy: 1)
        XCTAssertEqual(bar.frame.height, initialBar.height, accuracy: 1)
        attach(app, "compact-history")

        picker.buttons["Waiting"].tap()
        XCTAssertEqual(picker.frame.minY, initialPicker.minY, accuracy: 1)
        XCTAssertEqual(bar.frame.height, initialBar.height, accuracy: 1)
        XCTAssertTrue(app.buttons["Review Stripe live"].exists)
    }

    func testAccessibilityTextKeepsActionsReachable() {
        let app = launch(["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"])
        let review = app.buttons["Review Stripe live"]
        // A full-screen fling can skip both stacked actions at accessibility sizes.
        let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.70))
        let end = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.52))
        for _ in 0..<14 where !review.isHittable {
            start.press(forDuration: 0.1, thenDragTo: end)
        }
        attach(app, "native-accessibility-text")
        XCTAssertTrue(review.isHittable)
        XCTAssertGreaterThanOrEqual(review.frame.height, 44)
        let deny = app.buttons["Deny Stripe live"]
        XCTAssertTrue(deny.isHittable)
        XCTAssertGreaterThanOrEqual(deny.frame.height, 44)
        XCTAssertFalse(app.buttons["Allow Stripe live once"].exists)
    }

    private func attach(_ app: XCUIApplication, _ name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func openHistorySearch(_ app: XCUIApplication) {
        app.buttons["History options"].tap()
        app.buttons["Search History"].tap()
        XCTAssertTrue(app.searchFields.firstMatch.waitForExistence(timeout: 5))
    }
}
