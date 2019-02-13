// swift-tools-version:4.2

import PackageDescription

let package = Package(
    name: "GDisco",
    products: [
        .library(
            name: "GDisco",
            targets: ["GDisco"]),
    ],
    dependencies: [
        .package(url: "https://github.com/nixberg/GStrobe", from: "0.0.0"),
        .package(url: "https://github.com/nixberg/monocypher-swift", from: "0.0.1"),
    ],
    targets: [
        .target(
            name: "GDisco",
            dependencies: ["GStrobe", "Monocypher"]),
        .testTarget(
            name: "GDiscoTests",
            dependencies: ["GDisco"]),
    ]
)
