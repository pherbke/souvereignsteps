import CryptoKit
import Foundation
import GloveboxValidator

// Usage: glovebox-check <wallet_profile.json> <vectors.json> [repeats]
// Validates every vector, compares the observed code with the expected code
// recorded by the Python harness, and times validation of the accepted packages.

let args = CommandLine.arguments
guard args.count >= 3 else {
    FileHandle.standardError.write(Data("usage: glovebox-check <profile.json> <vectors.json> [repeats]\n".utf8))
    exit(2)
}
let repeats = args.count > 3 ? Int(args[3]) ?? 2000 : 2000
let profile = try WalletProfile(json: Data(contentsOf: URL(fileURLWithPath: args[1])))
let vectorData = try Data(contentsOf: URL(fileURLWithPath: args[2]))
guard let vectors = try JSONSerialization.jsonObject(with: vectorData) as? [[String: Any]] else { exit(2) }

func code(for jws: String, preinstall: [String] = []) -> String {
    var floors: [String: Int64] = [:]
    for earlier in preinstall { _ = try? Validator.install(Data(earlier.utf8), profile: profile, floors: &floors) }
    do {
        _ = try Validator.validate(Data(jws.utf8), profile: profile, floors: floors)
        return "ACCEPTED"
    } catch let rejection as Rejection {
        return rejection.code
    } catch {
        return "ERROR"
    }
}

func medianMicros(_ body: () -> Void) -> Double {
    var samples: [Double] = []
    samples.reserveCapacity(repeats)
    for _ in 0..<repeats {
        let start = DispatchTime.now().uptimeNanoseconds
        body()
        samples.append(Double(DispatchTime.now().uptimeNanoseconds - start) / 1000.0)
    }
    samples.sort()
    return samples[samples.count / 2]
}

var agreeing = 0
var cases: [[String: String]] = []
var timings: [String: Double] = [:]
for vector in vectors {
    guard let id = vector["id"] as? String, let expected = vector["expected"] as? String,
          let jws = vector["jws"] as? String else { continue }
    let observed = code(for: jws, preinstall: vector["preinstall"] as? [String] ?? [])
    if observed == expected { agreeing += 1 }
    cases.append(["id": id, "expected": expected, "observed": observed])
    if expected == "ACCEPTED" {
        let data = Data(jws.utf8)
        timings[id] = medianMicros { _ = try? Validator.validate(data, profile: profile) }
    }
}

let key = Curve25519.Signing.PrivateKey()
let message = Data(repeating: 0x78, count: 3000)
let signature = try key.signature(for: message)
let verifyMicros = medianMicros { _ = key.publicKey.isValidSignature(signature, for: message) }

var sysinfo = utsname()
uname(&sysinfo)
let machine = withUnsafeBytes(of: &sysinfo.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
var size = 0
sysctlbyname("machdep.cpu.brand_string", nil, &size, nil, 0)
var brand = [CChar](repeating: 0, count: size)
sysctlbyname("machdep.cpu.brand_string", &brand, &size, nil, 0)
let cpu = String(decoding: brand.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)

let medians = timings.values.sorted()
let result: [String: Any] = [
    "vectors": cases.count,
    "vectorsAgreeing": agreeing,
    "cases": cases,
    "validateMedianMicros": timings,
    "medianValidateUs": medians.isEmpty ? 0 : medians[medians.count / 2],
    "maxMedianValidateUs": medians.last ?? 0,
    "medianVerifyUs": verifyMicros,
    "repeats": repeats,
    "machine": cpu.isEmpty ? machine : cpu,
    "os": ProcessInfo.processInfo.operatingSystemVersionString,
]
let output = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
FileHandle.standardOutput.write(output)
FileHandle.standardOutput.write(Data("\n".utf8))
exit(agreeing == cases.count ? 0 : 1)
