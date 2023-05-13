// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CertificateSigningRequest",
    platforms: [.iOS(.v10),
        .macOS(.v10_13),
        .tvOS(.v10),
        .watchOS(.v3)],
    products: [
        .library(name: "CertificateSigningRequest",
                 targets: ["CertificateSigningRequest"])
    ],
    dependencies: [],
    targets: [
        .target(name: "CertificateSigningRequest"),
        .testTarget(name: "CertificateSigningRequestTests",
                    dependencies: ["CertificateSigningRequest"])
    ]
)
