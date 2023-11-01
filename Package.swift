// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "tkey_pkg",
    platforms: [
        .iOS(.v14), .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "ThresholdKey",
            targets: ["tkey-pkg"]),
    ],
    dependencies: [
        .package(name: "TorusUtils", url: "https://github.com/torusresearch/torus-utils-swift" , from: "6.1.0"),
        .package(name: "secp256k1", url: "https://github.com/GigaBitcoin/secp256k1.swift" , .exact("0.12.2")),
        // dev dependencies only
        .package(name:"CryptoSwift", url: "https://github.com/krzyzanowskim/CryptoSwift",from: "1.5.1"),
        .package(name:"jwt-kit", url: "https://github.com/vapor/jwt-kit", from: "4.0.0"),
    ],
    targets: [
        .binaryTarget(name: "libtkey",
                      path: "Sources/libtkey/libtkey.xcframework"
        ),
        .target(name: "lib",
               dependencies: ["libtkey"],
                path: "Sources/libtkey"
        ),
        .target(
            name: "tkey-pkg",
            dependencies: ["lib", "TorusUtils", "secp256k1"],
            path: "Sources/ThresholdKey"
        ),
        .testTarget(
            name: "tkey-pkgTests",
            dependencies: ["tkey-pkg", "CryptoSwift", .product(name: "JWTKit", package: "jwt-kit")],
            path: "Tests/tkeypkgTests"
        ),
    ],
    swiftLanguageVersions: [.v5]
)
