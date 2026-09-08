// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "FactorSealCredentialExchange",
    platforms: [.macOS(.v26)],
    products: [.library(name: "FactorSealCredentialExchange", targets: ["FactorSealCredentialExchange"])],
    targets: [
        .target(name: "FactorSealCredentialExchange"),
        .testTarget(
            name: "FactorSealCredentialExchangeTests",
            dependencies: ["FactorSealCredentialExchange"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
