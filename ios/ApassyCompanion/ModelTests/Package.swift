// swift-tools-version: 6.2
// Tests of the models of the app (SessionModel, PairingModel, and the vault models) on macOS with
// `swift test`.
//
// The models use no UIKit and no SwiftUI, so this package compiles the same source files as the
// app: Sources/AppModels holds symbolic links to them. It needs no iOS Simulator. The screens have
// no tests here; they are checked by the build and by the previews.

import PackageDescription

let package = Package(
    name: "ApassyCompanionModelTests",
    platforms: [
        .macOS(.v15)
    ],
    dependencies: [
        .package(path: "../../ApassyCompanionKit"),
        .package(path: "../../ApassyVaultKit"),
    ],
    targets: [
        .target(
            name: "AppModels",
            dependencies: [
                .product(name: "ApassyCompanionKit", package: "ApassyCompanionKit"),
                .product(name: "ApassyVaultKit", package: "ApassyVaultKit"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "AppModelsTests",
            dependencies: [
                "AppModels",
                .product(name: "ApassyCompanionKit", package: "ApassyCompanionKit"),
                .product(name: "ApassyVaultKit", package: "ApassyVaultKit"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
