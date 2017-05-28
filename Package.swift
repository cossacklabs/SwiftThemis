import PackageDescription

let package = Package(
    name: "SwiftThemis",
    dependencies: [
        .Package(url: "https://github.com/cossacklabs/SwiftCThemis", majorVersion: 0)
    ]
)
