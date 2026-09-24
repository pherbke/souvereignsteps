import Foundation

/// JSON values admitted in packages: no floating-point numbers.
public indirect enum JSONValue: Equatable {
    case object([String: JSONValue])
    case array([JSONValue])
    case string(String)
    case int(Int64)
    case bool(Bool)
    case null

    public var object: [String: JSONValue]? { if case .object(let o) = self { return o }; return nil }
    public var array: [JSONValue]? { if case .array(let a) = self { return a }; return nil }
    public var string: String? { if case .string(let s) = self { return s }; return nil }
    public var int: Int64? { if case .int(let i) = self { return i }; return nil }
}

public enum StrictJSONError: Error, Equatable {
    case duplicateKey(String)
    case malformed(String)
}

/// Recursive-descent parser that rejects duplicate object keys, fractions,
/// exponents, and trailing data. Foundation's JSONSerialization silently keeps
/// one of two duplicate keys, which would open a parser differential between
/// the wallet and any other tool that reads the same bytes.
public struct StrictJSONParser {
    private let bytes: [UInt8]
    private var index = 0
    private let maxDepth = 64

    public static func parse(_ data: Data) throws -> JSONValue {
        var parser = StrictJSONParser(bytes: Array(data))
        parser.skipWhitespace()
        let value = try parser.parseValue(depth: 0)
        parser.skipWhitespace()
        guard parser.index == parser.bytes.count else { throw StrictJSONError.malformed("trailing data") }
        return value
    }

    private init(bytes: [UInt8]) { self.bytes = bytes }

    private mutating func skipWhitespace() {
        while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
    }

    private func peek() -> UInt8? { index < bytes.count ? bytes[index] : nil }

    private mutating func expect(_ literal: String) throws {
        for byte in literal.utf8 {
            guard peek() == byte else { throw StrictJSONError.malformed("expected \(literal)") }
            index += 1
        }
    }

    private mutating func parseValue(depth: Int) throws -> JSONValue {
        guard depth < maxDepth else { throw StrictJSONError.malformed("nesting too deep") }
        guard let byte = peek() else { throw StrictJSONError.malformed("unexpected end") }
        switch byte {
        case UInt8(ascii: "{"): return try parseObject(depth: depth)
        case UInt8(ascii: "["): return try parseArray(depth: depth)
        case UInt8(ascii: "\""): return .string(try parseString())
        case UInt8(ascii: "t"): try expect("true"); return .bool(true)
        case UInt8(ascii: "f"): try expect("false"); return .bool(false)
        case UInt8(ascii: "n"): try expect("null"); return .null
        default: return .int(try parseInteger())
        }
    }

    private mutating func parseObject(depth: Int) throws -> JSONValue {
        index += 1
        var result: [String: JSONValue] = [:]
        skipWhitespace()
        if peek() == UInt8(ascii: "}") { index += 1; return .object(result) }
        while true {
            skipWhitespace()
            guard peek() == UInt8(ascii: "\"") else { throw StrictJSONError.malformed("expected key") }
            let key = try parseString()
            if result[key] != nil { throw StrictJSONError.duplicateKey(key) }
            skipWhitespace()
            try expect(":")
            skipWhitespace()
            result[key] = try parseValue(depth: depth + 1)
            skipWhitespace()
            if peek() == UInt8(ascii: ",") { index += 1; continue }
            try expect("}")
            return .object(result)
        }
    }

    private mutating func parseArray(depth: Int) throws -> JSONValue {
        index += 1
        var result: [JSONValue] = []
        skipWhitespace()
        if peek() == UInt8(ascii: "]") { index += 1; return .array(result) }
        while true {
            skipWhitespace()
            result.append(try parseValue(depth: depth + 1))
            skipWhitespace()
            if peek() == UInt8(ascii: ",") { index += 1; continue }
            try expect("]")
            return .array(result)
        }
    }

    private mutating func parseInteger() throws -> Int64 {
        let start = index
        if peek() == UInt8(ascii: "-") { index += 1 }
        guard let first = peek(), (0x30...0x39).contains(first) else {
            throw StrictJSONError.malformed("invalid value")
        }
        if first == 0x30 { index += 1 } else {
            while let b = peek(), (0x30...0x39).contains(b) { index += 1 }
        }
        if let b = peek(), b == UInt8(ascii: ".") || b == UInt8(ascii: "e") || b == UInt8(ascii: "E") {
            throw StrictJSONError.malformed("floating-point numbers are not permitted")
        }
        let text = String(decoding: bytes[start..<index], as: UTF8.self)
        guard let value = Int64(text), abs(value) <= 9_007_199_254_740_991 else {
            throw StrictJSONError.malformed("integer outside the safe range")
        }
        return value
    }

    private mutating func parseString() throws -> String {
        index += 1
        var scalars = String.UnicodeScalarView()
        var raw: [UInt8] = []
        func flush() throws {
            if raw.isEmpty { return }
            guard let text = String(bytes: raw, encoding: .utf8) else {
                throw StrictJSONError.malformed("invalid UTF-8")
            }
            scalars.append(contentsOf: text.unicodeScalars)
            raw.removeAll()
        }
        while true {
            guard let byte = peek() else { throw StrictJSONError.malformed("unterminated string") }
            index += 1
            if byte == UInt8(ascii: "\"") { try flush(); return String(scalars) }
            if byte < 0x20 { throw StrictJSONError.malformed("control character in string") }
            if byte != UInt8(ascii: "\\") { raw.append(byte); continue }
            try flush()
            guard let esc = peek() else { throw StrictJSONError.malformed("bad escape") }
            index += 1
            switch esc {
            case UInt8(ascii: "\""): scalars.append("\"")
            case UInt8(ascii: "\\"): scalars.append("\\")
            case UInt8(ascii: "/"): scalars.append("/")
            case UInt8(ascii: "b"): scalars.append("\u{08}")
            case UInt8(ascii: "f"): scalars.append("\u{0C}")
            case UInt8(ascii: "n"): scalars.append("\n")
            case UInt8(ascii: "r"): scalars.append("\r")
            case UInt8(ascii: "t"): scalars.append("\t")
            case UInt8(ascii: "u"):
                var code = try parseHex4()
                if (0xD800...0xDBFF).contains(code) {
                    try expect("\\u")
                    let low = try parseHex4()
                    guard (0xDC00...0xDFFF).contains(low) else { throw StrictJSONError.malformed("bad surrogate") }
                    code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                }
                guard let scalar = Unicode.Scalar(code) else { throw StrictJSONError.malformed("bad escape") }
                scalars.append(scalar)
            default:
                throw StrictJSONError.malformed("bad escape")
            }
        }
    }

    private mutating func parseHex4() throws -> UInt32 {
        guard index + 4 <= bytes.count,
              let value = UInt32(String(decoding: bytes[index..<index + 4], as: UTF8.self), radix: 16)
        else { throw StrictJSONError.malformed("bad \\u escape") }
        index += 4
        return value
    }
}
