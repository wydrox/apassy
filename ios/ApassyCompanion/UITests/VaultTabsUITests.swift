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
}
