// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "FactorSealCredentialExchange",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "FactorSealCredentialExchange", targets: ["FactorSealCredentialExchange"]),
        .library(name: "FactorSealAppleBridge", type: .dynamic, targets: ["FactorSealAppleBridge"]),
    ],
    targets: [
        .target(name: "FactorSealCredentialExchange"),
        .target(name: "FactorSealAppleBridge", dependencies: ["FactorSealCredentialExchange"]),
        .testTarget(
            name: "FactorSealCredentialExchangeTests",
            dependencies: ["FactorSealCredentialExchange", "FactorSealAppleBridge"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
