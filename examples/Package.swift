import PackageDescription

let package = Package(
    name: "ThemisTest",
    dependencies: [
        .Package(url: "https://github.com/cossacklabs/SwiftThemis", majorVersion: 0)
    ]
)
