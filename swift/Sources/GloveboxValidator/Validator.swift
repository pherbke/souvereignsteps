import CryptoKit
import Foundation

/// Wallet-side package validator. It mirrors the reference Python validator
/// check by check and reports the same error codes, so both implementations can
/// be tested differentially against the same vectors.
public struct Rejection: Error, Equatable {
    public let code: String
    public let detail: String
}

public struct ValidatedPackage {
    public let package: [String: JSONValue]
    public let kid: String
}

public struct WalletProfile {
    let schemas: Set<String>
    let handlers: [String: JSONValue]
    let publishers: [String: JSONValue]
    let versionFloors: [String: Int64]
    let limits: [String: Int64]
    let keys: [String: Curve25519.Signing.PublicKey]
    public let clock: Date

    public init(json data: Data) throws {
        guard let root = try StrictJSONParser.parse(data).object else { throw Rejection(code: "E_PROFILE", detail: "") }
        schemas = Set(root["schemas"]?.array?.compactMap { $0.string } ?? [])
        handlers = root["handlers"]?.object ?? [:]
        publishers = root["publishers"]?.object ?? [:]
        versionFloors = (root["versionFloors"]?.object ?? [:]).compactMapValues { $0.int }
        limits = (root["limits"]?.object ?? [:]).compactMapValues { $0.int }
        var keys: [String: Curve25519.Signing.PublicKey] = [:]
        for (kid, entry) in publishers {
            if let hex = entry.object?["publicKey"]?.string, let raw = Data(hexString: hex) {
                keys[kid] = try Curve25519.Signing.PublicKey(rawRepresentation: raw)
            }
        }
        self.keys = keys
        guard let clock = root["clock"]?.string.flatMap(Validator.parseTime) else {
            throw Rejection(code: "E_PROFILE", detail: "clock")
        }
        self.clock = clock
    }

    func locality(_ action: [String: JSONValue]) -> String? {
        guard let type = action["type"]?.string, let spec = handlers[type]?.object?["locality"] else { return nil }
        if let fixed = spec.string { return fixed }
        guard let rule = spec.object, let param = rule["byParam"]?.string,
              let value = action["params"]?.object?[param]?.string else { return nil }
        return rule["map"]?.object?[value]?.string
    }
}

public enum Validator {
    static let packageType = "glovebox-package+json"
    static let packageFields: Set<String> = ["schema", "id", "version", "floor", "notAfter", "initial", "states"]
    static let terminalKinds: Set<String> = ["success", "deny", "error"]

    /// Parses the fixed UTC form yyyy-MM-ddTHH:mm:ssZ without a locale-dependent formatter.
    static func parseTime(_ text: String) -> Date? {
        let b = Array(text.utf8)
        guard b.count == 20, b[4] == 0x2D, b[7] == 0x2D, b[10] == 0x54, b[13] == 0x3A, b[16] == 0x3A,
              b[19] == 0x5A else { return nil }
        func num(_ range: Range<Int>) -> Int? {
            var value = 0
            for i in range {
                guard (0x30...0x39).contains(b[i]) else { return nil }
                value = value * 10 + Int(b[i] - 0x30)
            }
            return value
        }
        guard let y = num(0..<4), let m = num(5..<7), let d = num(8..<10), let hh = num(11..<13),
              let mm = num(14..<16), let ss = num(17..<19), (1...12).contains(m), (1...31).contains(d),
              hh < 24, mm < 60, ss < 60 else { return nil }
        // Days from the civil calendar (H. Hinnant's algorithm).
        let yy = m <= 2 ? y - 1 : y
        let era = (yy >= 0 ? yy : yy - 399) / 400
        let yoe = yy - era * 400
        let doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        let days = era * 146_097 + doe - 719_468
        return Date(timeIntervalSince1970: TimeInterval(days * 86_400 + hh * 3600 + mm * 60 + ss))
    }

    static func reject(_ code: String, _ detail: String = "") -> Rejection {
        Rejection(code: code, detail: detail)
    }

    /// `floors` holds the highest signed floor this wallet has accepted per package identifier.
    public static func validate(_ raw: Data, profile: WalletProfile, now: Date? = nil,
                                floors: [String: Int64] = [:]) throws -> ValidatedPackage {
        let now = now ?? profile.clock
        guard raw.count <= Int(profile.limits["maxPackageBytes"] ?? 16384) else { throw reject("E_LIMITS") }

        // 1. Envelope.
        guard let text = String(data: raw, encoding: .ascii) else { throw reject("E_PARSE") }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        if parts.count == 2 || (parts.count == 3 && parts[2].isEmpty) { throw reject("E_SIG_MISSING") }
        guard parts.count == 3, let headerData = Data(base64URL: parts[0]),
              let payload = Data(base64URL: parts[1]), let signature = Data(base64URL: parts[2])
        else { throw reject("E_PARSE") }
        guard let header = try? StrictJSONParser.parse(headerData).object,
              header["typ"]?.string == packageType else { throw reject("E_PARSE") }

        // 2. Authenticity.
        guard header["alg"]?.string == "EdDSA" else { throw reject("E_SIG_INVALID") }
        guard let kid = header["kid"]?.string, let key = profile.keys[kid],
              let publisher = profile.publishers[kid]?.object else { throw reject("E_UNKNOWN_KEY") }
        let signingInput = Data((parts[0] + "." + parts[1]).utf8)
        guard key.isValidSignature(signature, for: signingInput) else { throw reject("E_SIG_INVALID") }

        // 3. Strict payload parsing.
        let parsed: JSONValue
        do { parsed = try StrictJSONParser.parse(payload) }
        catch StrictJSONError.duplicateKey(let key) { throw reject("E_DUPLICATE_KEY", key) }
        catch { throw reject("E_PARSE") }
        guard let package = parsed.object else { throw reject("E_PARSE") }

        // 4. Schema and namespace.
        guard let schema = package["schema"]?.string, profile.schemas.contains(schema) else { throw reject("E_SCHEMA") }
        guard Set(package.keys) == packageFields, let pid = package["id"]?.string,
              let version = package["version"]?.int, version >= 1,
              let floor = package["floor"]?.int, floor >= 1, floor <= version,
              let states = package["states"]?.object, let initial = package["initial"]?.string
        else { throw reject("E_SCHEMA") }
        let namespaces = publisher["namespaces"]?.array?.compactMap { $0.string } ?? []
        guard namespaces.contains(where: { pid.hasPrefix($0) }) else { throw reject("E_NAMESPACE") }

        // 5. Lifecycle.
        guard let notAfter = package["notAfter"]?.string.flatMap(parseTime) else { throw reject("E_SCHEMA") }
        if now > notAfter { throw reject("E_EXPIRED") }
        if version < max(profile.versionFloors[pid] ?? 1, floors[pid] ?? 1) { throw reject("E_ROLLBACK") }
        if states.count > Int(profile.limits["maxStates"] ?? 64) { throw reject("E_LIMITS") }

        // 6. Graph integrity.
        try checkGraph(states: states, initial: initial)

        // 7. Typing, capability, disclosure, endpoints, offline outcomes.
        let origins = Set(publisher["origins"]?.array?.compactMap { $0.string } ?? [])
        let granted = Set(publisher["handlers"]?.array?.compactMap { $0.string } ?? [])
        for sid in states.keys.sorted() {
            guard let state = states[sid]?.object, state["terminal"] == nil else { continue }
            guard let action = state["action"]?.object, let type = action["type"]?.string,
                  let spec = profile.handlers[type]?.object else { throw reject("E_UNKNOWN_ACTION", sid) }
            guard granted.contains(type) else { throw reject("E_PUBLISHER_SCOPE", sid) }
            guard Set(action.keys).isSubset(of: ["type", "params"]) else { throw reject("E_SCHEMA", sid) }
            try checkParams(sid: sid, params: action["params"] ?? .object([:]), spec: spec,
                            limits: profile.limits, origins: origins)
            let declared = Set(spec["outcomes"]?.array?.compactMap { $0.string } ?? [])
            let on = state["on"]?.object ?? [:]
            for outcome in on.keys where !declared.contains(outcome) { throw reject("E_UNDECLARED_OUTCOME", sid) }
            if profile.locality(action) == "network" && on["offline"] == nil { throw reject("E_OFFLINE_UNMAPPED", sid) }
        }
        return ValidatedPackage(package: package, kid: kid)
    }

    /// Validate against the stored floors, then ratchet the floor for this package identifier.
    @discardableResult
    public static func install(_ raw: Data, profile: WalletProfile, floors: inout [String: Int64],
                               now: Date? = nil) throws -> ValidatedPackage {
        let validated = try validate(raw, profile: profile, now: now, floors: floors)
        if let pid = validated.package["id"]?.string, let floor = validated.package["floor"]?.int {
            floors[pid] = max(floors[pid] ?? 1, floor)
        }
        return validated
    }

    static func checkGraph(states: [String: JSONValue], initial: String) throws {
        guard let first = states[initial]?.object, first["terminal"] == nil else { throw reject("E_BAD_INITIAL") }
        for sid in states.keys.sorted() {
            guard let state = states[sid]?.object else { throw reject("E_SCHEMA", sid) }
            if let terminal = state["terminal"] {
                guard state.count == 1, let kind = terminal.string, terminalKinds.contains(kind) else {
                    throw reject("E_TERMINAL", sid)
                }
                continue
            }
            guard Set(state.keys) == ["action", "on"], state["action"]?.object != nil else { throw reject("E_SCHEMA", sid) }
            guard let on = state["on"]?.object, !on.isEmpty else { throw reject("E_DANGLING", sid) }
            for target in on.values {
                guard let name = target.string, states[name] != nil else { throw reject("E_DANGLING", sid) }
            }
        }
        func successors(_ sid: String) -> [String] {
            (states[sid]?.object?["on"]?.object ?? [:]).values.compactMap { $0.string }
        }
        var reached: Set<String> = [initial]
        var frontier = [initial]
        while let sid = frontier.popLast() {
            for next in successors(sid) where !reached.contains(next) {
                reached.insert(next)
                frontier.append(next)
            }
        }
        if reached.count != states.count { throw reject("E_UNREACHABLE") }
        var colour: [String: Int] = [:]
        func visit(_ sid: String) throws {
            colour[sid] = 1
            for next in successors(sid) {
                if colour[next] == 1 { throw reject("E_CYCLE", sid) }
                if colour[next] == nil { try visit(next) }
            }
            colour[sid] = 2
        }
        try visit(initial)
    }

    static func checkParams(sid: String, params: JSONValue, spec: [String: JSONValue],
                            limits: [String: Int64], origins: Set<String>) throws {
        guard let params = params.object else { throw reject("E_PARAM", sid) }
        let rules = spec["params"]?.object ?? [:]
        if !Set(params.keys).isSubset(of: Set(rules.keys)) { throw reject("E_PARAM", sid) }
        let maxString = Int(limits["maxStringLength"] ?? 512)
        let maxList = Int(limits["maxListLength"] ?? 32)
        for name in rules.keys.sorted() {
            guard let rule = rules[name]?.object, let kind = rule["type"]?.string else { continue }
            var required = rule["required"] == .bool(true)
            if let condition = rule["requiredIf"]?.object {
                required = condition.allSatisfy { params[$0.key] == $0.value }
            }
            guard let value = params[name] else {
                if required { throw reject("E_PARAM", "\(sid): missing \(name)") }
                continue
            }
            switch kind {
            case "list":
                guard let items = value.array else { throw reject("E_PARAM", sid) }
                if rule["disclosure"] == .bool(true) && items.isEmpty { throw reject("E_EMPTY_DISCLOSURE", sid) }
                let strings = items.compactMap { $0.string }
                guard !items.isEmpty, items.count <= maxList, strings.count == items.count,
                      Set(strings).count == strings.count,
                      strings.allSatisfy({ !$0.isEmpty && $0.count <= maxString }) else { throw reject("E_PARAM", sid) }
            case "enum":
                let allowed = rule["values"]?.array ?? []
                guard allowed.contains(value) else { throw reject("E_PARAM", sid) }
            case "string":
                guard let s = value.string, !s.isEmpty, s.count <= maxString else { throw reject("E_PARAM", sid) }
            case "decimal":
                guard let s = value.string, isDecimal(s) else { throw reject("E_PARAM", sid) }
            case "endpoint":
                guard let s = value.string, let o = origin(s), origins.contains(o) else { throw reject("E_ENDPOINT", sid) }
            default:
                throw reject("E_PARAM", sid)
            }
        }
    }

    static func isDecimal(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        func digits(_ p: Substring, _ range: ClosedRange<Int>) -> Bool {
            range.contains(p.count) && p.allSatisfy { $0.isASCII && $0.isNumber }
        }
        if parts.count == 1 { return digits(parts[0], 1...6) }
        return parts.count == 2 && digits(parts[0], 1...6) && digits(parts[1], 1...2)
    }

    static func origin(_ url: String) -> String? {
        guard let c = URLComponents(string: url), c.scheme == "https", let host = c.host, !host.isEmpty,
              c.user == nil, c.password == nil else { return nil }
        return "https://" + host.lowercased() + (c.port.map { ":\($0)" } ?? "")
    }
}

extension Data {
    init?(base64URL text: String) {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        if s.contains("=") { return nil }
        s += String(repeating: "=", count: (4 - s.count % 4) % 4)
        self.init(base64Encoded: s)
    }

    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
