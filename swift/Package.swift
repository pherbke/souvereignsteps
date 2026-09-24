// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "GloveboxValidator",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "GloveboxValidator", targets: ["GloveboxValidator"]),
        .executable(name: "glovebox-check", targets: ["glovebox-check"]),
    ],
    targets: [
        .target(name: "GloveboxValidator"),
        .executableTarget(name: "glovebox-check", dependencies: ["GloveboxValidator"]),
    ]
)
