import XCTest

/// One dedicated Simulator with in-memory vault data; no real relay or owner Keychain.
@MainActor
final class ConnectUITests: XCTestCase {
    func testPairingSafetyWordsThenRequestsAndNotificationChoice() {
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launchArguments = ["-ApassyPreviewVault", "-ApassyPreviewUnlocked", "-ApassyOpen", "decisions",
            "-ApassyConnectLink", "https://relay.example.test/link#apassy_lnk_t_7k2m5q4x3c_0000000000000000000000000000000000000000000000000000000000000000&handoff=2.AQEBAQEBAQEBAQEBAQEBAQ.AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI.BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA"]
        app.launch()
        XCTAssertTrue(app.navigationBars["Connect this iPhone"].waitForExistence(timeout: 15))
        XCTAssertTrue(app.staticTexts["amber marble cedar river panda tulip"].waitForExistence(timeout: 5))
        capture(app, "iphone-connect-safety-words")
        XCTAssertTrue(app.buttons["Open Requests"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.switches["Request Notifications"].exists)
        capture(app, "iphone-connect-success")
        app.buttons["Open Requests"].tap()
        XCTAssertTrue(app.segmentedControls["requests.destination"].waitForExistence(timeout: 5))
        capture(app, "iphone-connect-requests")
    }

    func testPairingInstructionsHaveNoAccountOrTeamCodeStep() {
        let app = XCUIApplication()
        app.launchArguments = ["-ApassyPreviewVault", "-ApassyPreviewUnlocked", "-ApassyOpen", "decisions"]
        app.launch()
        let connect = app.buttons["Connect this iPhone"]
        XCTAssertTrue(connect.waitForExistence(timeout: 15))
        connect.tap()
        XCTAssertTrue(app.textFields["Name of this iPhone"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "Get approvals on your iPhone")).firstMatch.exists)
        XCTAssertFalse(app.textFields["Team code"].exists)
        capture(app, "iphone-connect-pairing")
        app.buttons["Cancel"].tap()
    }

    private func capture(_ app: XCUIApplication, _ name: String) {
        let screenshot = app.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
