// Glovebox: installation of signed process packages and their version floors.
//
// A package is installed only after validation against the wallet profile and
// the floors this wallet has already accepted. The floor travels inside the
// signed payload, so only the publisher that may publish a package identifier
// can raise it; the store keeps the highest floor ever accepted and persists it.
// A forced update is a package whose floor equals its version: once installed,
// older packages for the same identifier no longer validate, even offline.
// Packages are kept per version, so a run stays on the version it started with.

import Foundation

final class GloveboxPackageStore {
    static let shared = GloveboxPackageStore()

    let profile: WalletProfile
    private let defaults: UserDefaults
    private let floorsKey = "glovebox.floors"
    private let packagePrefix = "glovebox.package."

    init(defaults: UserDefaults = .standard, profile: WalletProfile? = nil) {
        self.defaults = defaults
        if let profile {
            self.profile = profile
        } else {
            self.profile = GloveboxPackageStore.loadBundledProfile()
        }
    }

    static func loadBundledProfile() -> WalletProfile {
        guard let url = Bundle.main.url(forResource: "glovebox_wallet_profile", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let profile = try? WalletProfile(json: data) else {
            fatalError("glovebox_wallet_profile.json is missing or malformed")
        }
        return profile
    }

    var floors: [String: Int64] {
        (defaults.dictionary(forKey: floorsKey) as? [String: Int64]) ?? [:]
    }

    /// Validates, ratchets the floor, and persists the package bytes.
    @discardableResult
    func install(_ jws: String, now: Date = Date()) throws -> ValidatedPackage {
        var floors = self.floors
        let validated = try Validator.install(Data(jws.utf8), profile: profile, floors: &floors, now: now)
        guard let pid = validated.package["id"]?.string, let version = validated.package["version"]?.int else {
            throw Rejection(code: "E_SCHEMA", detail: "id")
        }
        defaults.set(floors, forKey: floorsKey)
        defaults.set(jws, forKey: packagePrefix + pid)
        defaults.set(jws, forKey: "\(packagePrefix)\(pid)@\(version)")
        return validated
    }

    /// Re-validates a cached package against the current floors and clock before every use.
    /// Without a version, the most recently installed version is returned.
    func package(id: String, version: Int64? = nil, now: Date = Date()) throws -> ValidatedPackage {
        let key = version.map { "\(packagePrefix)\(id)@\($0)" } ?? packagePrefix + id
        guard let jws = defaults.string(forKey: key) else {
            throw Rejection(code: "E_NOT_INSTALLED", detail: id)
        }
        return try Validator.validate(Data(jws.utf8), profile: profile, now: now, floors: floors)
    }

    func removeAll() {
        for key in defaults.dictionaryRepresentation().keys where key.hasPrefix(packagePrefix) {
            defaults.removeObject(forKey: key)
        }
        defaults.removeObject(forKey: floorsKey)
    }
}
