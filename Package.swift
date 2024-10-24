// swift-tools-version: 5.4
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JWTGenSwift",
    platforms: [
        .iOS(.v14)
    ],
    products: [
        .library(
            name: "JWTGenSwift",
            targets: ["JWTGenSwift"]
        )
    ],
    targets: [
        .target(
            name: "JWTGenSwift"
        )
    ]
)
