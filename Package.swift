// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "sentinel",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "SentinelCore", targets: ["SentinelCore"]),
        .executable(name: "sentinel", targets: ["SentinelApp"]),
    ],
    targets: [
        .target(name: "SentinelCore"),
        .executableTarget(name: "SentinelApp", dependencies: ["SentinelCore"]),
        // XCTest needs full Xcode - this assert runner works with CLT only
        .executableTarget(name: "sentinel-test", dependencies: ["SentinelCore"]),
    ]
)
