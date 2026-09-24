//
//  GloveboxWalletTests.swift
//  PrototypeWalletTests
//
//  Runs the Glovebox layer inside the wallet app (simulator or device):
//  the reference vectors, path replay, fail-closed behavior, the install path for
//  verifier responses, floor persistence, and latency measurements. Metrics are
//  printed as lines starting with GLOVEBOX_METRIC.
//

import BBSCoreIOS
import CryptoKit
import eudi_lib_sdjwt_swift
import JSONWebSignature
import SwiftyJSON
import UIKit
import XCTest
@testable import PrototypeWallet

final class GloveboxWalletTests: XCTestCase {

    // MARK: Fixtures

    private struct PathSpec { let steps: [(String, String)]; let terminal: String; let remoteCount: Int }
    private struct PackageSpec { let name: String; let jws: String; let states: Int; let paths: [PathSpec] }

    private lazy var profile = GloveboxPackageStore.loadBundledProfile()

    private func resource(_ name: String) throws -> Data {
        let bundle = Bundle(for: GloveboxWalletTests.self)
        guard let url = bundle.url(forResource: name, withExtension: "json") else {
            throw XCTSkip("missing test resource \(name).json")
        }
        return try Data(contentsOf: url)
    }

    private func vectors() throws -> [[String: Any]] {
        try JSONSerialization.jsonObject(with: resource("glovebox_vectors")) as? [[String: Any]] ?? []
    }

    private func packages() throws -> [PackageSpec] {
        let root = try JSONSerialization.jsonObject(with: resource("glovebox_packages")) as? [String: [String: Any]] ?? [:]
        return root.keys.sorted().map { name in
            let entry = root[name]!
            let paths = (entry["paths"] as? [[String: Any]] ?? []).map { p -> PathSpec in
                let steps = (p["steps"] as? [String] ?? []).map { step -> (String, String) in
                    let parts = step.split(separator: ":", maxSplits: 1).map(String.init)
                    return (parts[0], parts[1])
                }
                return PathSpec(steps: steps, terminal: p["terminal"] as? String ?? "",
                                remoteCount: p["remoteCount"] as? Int ?? -1)
            }
            return PackageSpec(name: name, jws: entry["jws"] as? String ?? "",
                               states: entry["states"] as? Int ?? 0, paths: paths)
        }
    }

    private func isolatedStore(_ suite: String = UUID().uuidString) -> GloveboxPackageStore {
        let defaults = UserDefaults(suiteName: "glovebox.tests.\(suite)")!
        defaults.removePersistentDomain(forName: "glovebox.tests.\(suite)")
        return GloveboxPackageStore(defaults: defaults, profile: profile)
    }

    private func code(of jws: String, floors: [String: Int64] = [:]) -> String {
        do {
            _ = try Validator.validate(Data(jws.utf8), profile: profile, floors: floors)
            return "ACCEPTED"
        } catch let rejection as Rejection {
            return rejection.code
        } catch {
            return "ERROR"
        }
    }

    // MARK: Behavior

    /// All reference vectors yield the reference implementation's code inside the wallet.
    func testReferenceVectorsMatchReferenceImplementation() throws {
        var agreeing = 0
        let all = try vectors()
        for vector in all {
            var floors: [String: Int64] = [:]
            for earlier in vector["preinstall"] as? [String] ?? [] {
                _ = try? Validator.install(Data(earlier.utf8), profile: profile, floors: &floors)
            }
            let observed = code(of: vector["jws"] as? String ?? "", floors: floors)
            let expected = vector["expected"] as? String ?? ""
            XCTAssertEqual(observed, expected, "vector \(vector["id"] ?? "?")")
            if observed == expected { agreeing += 1 }
        }
        emit(["metric": "vectors", "agreeing": agreeing, "total": all.count])
    }

    /// Every enumerated path reaches the predicted terminal state with the predicted network steps.
    func testPathReplayMatchesStaticAnalysis() async throws {
        var replayed = 0, agreeing = 0
        for spec in try packages() {
            let validated = try Validator.validate(Data(spec.jws.utf8), profile: profile)
            let runtime = GloveboxRuntime(validated: validated, profile: profile)
            for path in spec.paths {
                let script = Dictionary(uniqueKeysWithValues: path.steps)
                let trace = await runtime.run { state, _ in script[state] ?? "missing" }
                replayed += 1
                if trace.terminal == path.terminal && trace.remote.count == path.remoteCount { agreeing += 1 }
                XCTAssertEqual(trace.terminal, path.terminal, "\(spec.name) path to \(path.terminal)")
                XCTAssertEqual(trace.remote.count, path.remoteCount, "\(spec.name) network steps")
            }
        }
        emit(["metric": "pathReplay", "agreeing": agreeing, "replayed": replayed])
    }

    /// A verifier naming a target state, or an unmapped outcome, ends the run fail-closed.
    func testRuntimeFailsClosed() async throws {
        let hotel = try packages().first { $0.name == "hotel-checkin" }!
        let runtime = GloveboxRuntime(validated: try Validator.validate(Data(hotel.jws.utf8), profile: profile),
                                      profile: profile)
        let forced = await runtime.run { state, _ in state == "PresentCheckIn" ? "ActivateRemote" : "success" }
        XCTAssertEqual(forced.kind, "error")
        XCTAssertEqual(forced.reason, "E_UNDECLARED_OUTCOME")
        XCTAssertFalse(forced.steps.contains { $0.state == "ActivateRemote" })

        let inspection = try packages().first { $0.name == "transit-inspection" }!
        let runtime2 = GloveboxRuntime(validated: try Validator.validate(Data(inspection.jws.utf8), profile: profile),
                                       profile: profile)
        let unmapped = await runtime2.run { state, _ in state == "PresentProof" ? "offline" : "success" }
        XCTAssertEqual(unmapped.reason, "E_UNMAPPED_OUTCOME")
    }

    /// The wallet's response handling installs signed packages and ignores unsigned statecharts.
    func testVerifierResponseHandling() throws {
        let store = isolatedStore()
        let hotel = try packages().first { $0.name == "hotel-checkin" }!
        XCTAssertEqual(GloveboxWallet.handle(packageJWS: hotel.jws, legacyStatechart: nil, store: store, now: profile.clock),
                       .installed(packageId: "com.example.hotel.checkin"))
        let tampered = try vectors().first { $0["id"] as? String == "A1" }!["jws"] as! String
        XCTAssertEqual(GloveboxWallet.handle(packageJWS: tampered, legacyStatechart: nil, store: store, now: profile.clock),
                       .rejected(code: "E_SIG_INVALID"))
        let previous = GloveboxWallet.allowLegacyStatecharts
        GloveboxWallet.allowLegacyStatecharts = false
        defer { GloveboxWallet.allowLegacyStatecharts = previous }
        XCTAssertEqual(GloveboxWallet.handle(packageJWS: nil, legacyStatechart: "{\"id\":\"X\"}", store: store),
                       .legacyRejected)
    }

    /// A forced update raises the persisted floor; the superseded version stays rejected across restarts.
    func testFloorRatchetPersists() throws {
        let suite = UUID().uuidString
        let store = isolatedStore(suite)
        let l4 = try vectors().first { $0["id"] as? String == "L4" }!
        let current = l4["jws"] as! String
        let forced = (l4["preinstall"] as! [String])[0]
        XCTAssertNoThrow(try store.install(current, now: profile.clock))
        XCTAssertNoThrow(try store.install(forced, now: profile.clock))
        XCTAssertThrowsError(try store.install(current, now: profile.clock)) { error in
            XCTAssertEqual((error as? Rejection)?.code, "E_ROLLBACK")
        }
        let restarted = GloveboxPackageStore(defaults: UserDefaults(suiteName: "glovebox.tests.\(suite)")!, profile: profile)
        XCTAssertEqual(restarted.floors["com.example.hotel.checkin"], 4)
        XCTAssertThrowsError(try restarted.install(current, now: profile.clock))
    }

    // MARK: Runs inside the wallet

    private func isolatedDriver() -> (GloveboxProcessDriver, GloveboxPackageStore, String) {
        let suite = "glovebox.tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        let store = GloveboxPackageStore(defaults: defaults, profile: profile)
        let driver = GloveboxProcessDriver(store: store, defaults: defaults, automatic: [
            "VERIFY_LOCAL_CREDENTIAL": { _, _ in "success" },
            "USER_NOTIFICATION": { _, _ in "success" },
            "LOG_EVENT": { _, _ in "success" },
        ])
        return (driver, store, suite)
    }

    /// The hotel check-in runs end to end through the wallet's driver: automatic local steps,
    /// the presentation outcome, the user's confirmations; verifier-named states are impossible.
    func testDriverRunsHotelCheckIn() throws {
        let (driver, store, suite) = isolatedDriver()
        defer { UserDefaults.standard.removePersistentDomain(forName: suite) }
        let hotel = try packages().first { $0.name == "hotel-checkin" }!
        let pid = "com.example.hotel.checkin"
        let now = profile.clock
        try store.install(hotel.jws, now: now)

        XCTAssertEqual(driver.start(credentialId: "res-1", packageId: pid, now: now),
                       .waiting(state: "PresentCheckIn", handler: "PRESENT_CREDENTIAL"))
        XCTAssertEqual(driver.confirm(credentialId: "res-1", now: now),
                       .ignored(state: "PresentCheckIn", reason: "E_NOT_USER_CONFIRMED"))
        XCTAssertEqual(driver.report(credentialId: "res-1", handler: "REQUEST_VC", outcome: "success", now: now),
                       .ignored(state: "PresentCheckIn", reason: "E_HANDLER_MISMATCH"))
        XCTAssertEqual(driver.report(credentialId: "res-1", handler: "PRESENT_CREDENTIAL", outcome: "success", now: now),
                       .waiting(state: "ConfirmCityTax", handler: "REQUEST_USER_INPUT"))
        XCTAssertEqual(driver.confirm(credentialId: "res-1", now: now),
                       .waiting(state: "PayCityTax", handler: "PROCESS_PAYMENT"))
        XCTAssertEqual(driver.confirm(credentialId: "res-1", now: now),
                       .waiting(state: "RequestRoomKey", handler: "REQUEST_VC"))
        XCTAssertEqual(driver.confirm(credentialId: "res-1", now: now),
                       .waiting(state: "ActivateRemote", handler: "ACTIVATE_REMOTE_CONTROL"))
        XCTAssertEqual(driver.confirm(credentialId: "res-1", now: now),
                       .finished(state: "EndCheckedIn", kind: "success"))
        XCTAssertEqual(driver.run(for: "res-1")?.ended, "success")
        XCTAssertFalse(driver.isActive("res-1"))

        // A denied presentation takes the declared fallback; offline takes the declared offline exit.
        driver.start(credentialId: "res-2", packageId: pid, now: now)
        XCTAssertEqual(driver.report(credentialId: "res-2", handler: "PRESENT_CREDENTIAL", outcome: "failure", now: now),
                       .finished(state: "EndFallback", kind: "deny"))
        driver.start(credentialId: "res-3", packageId: pid, now: now)
        XCTAssertEqual(driver.report(credentialId: "res-3", handler: "PRESENT_CREDENTIAL", outcome: "offline", now: now),
                       .finished(state: "EndOffline", kind: "error"))

        // An outcome outside the handler's alphabet (a verifier naming a state) fails closed.
        driver.start(credentialId: "res-4", packageId: pid, now: now)
        XCTAssertEqual(driver.report(credentialId: "res-4", handler: "PRESENT_CREDENTIAL", outcome: "ActivateRemote", now: now),
                       .failedClosed(state: "PresentCheckIn", reason: "E_UNDECLARED_OUTCOME"))

        // An expired package stops a run in flight at its next step.
        driver.start(credentialId: "res-5", packageId: pid, now: now)
        let later = now.addingTimeInterval(500 * 86400)
        XCTAssertEqual(driver.report(credentialId: "res-5", handler: "PRESENT_CREDENTIAL", outcome: "success", now: later),
                       .failedClosed(state: "PresentCheckIn", reason: "E_EXPIRED"))

        // A forced update raises the floor: runs in flight stop at their next step; new runs use it.
        driver.start(credentialId: "res-6", packageId: pid, now: now)
        let forced = (try vectors().first { $0["id"] as? String == "L4" }!["preinstall"] as! [String])[0]
        try store.install(forced, now: now)
        XCTAssertEqual(driver.report(credentialId: "res-6", handler: "PRESENT_CREDENTIAL", outcome: "success", now: now),
                       .failedClosed(state: "PresentCheckIn", reason: "E_ROLLBACK"))
        driver.start(credentialId: "res-7", packageId: pid, now: now)
        XCTAssertEqual(driver.run(for: "res-7")?.version, 4)
        XCTAssertTrue(driver.isActive("res-7"))
    }

    /// The display statechart derived from a package parses in the wallet's process screens.
    func testDisplayStatechartParses() throws {
        let hotel = try packages().first { $0.name == "hotel-checkin" }!
        let validated = try Validator.validate(Data(hotel.jws.utf8), profile: profile)
        let chart = try XCTUnwrap(GloveboxProcessDriver.displayStatechart(validated))
        let machine = try JSONDecoder().decode(XState.self, from: Data(chart.utf8))
        XCTAssertEqual(machine.id, "glovebox:com.example.hotel.checkin@3")
        XCTAssertEqual(machine.initial, "VerifyReservation")
        XCTAssertEqual(machine.states.count, 12)
        XCTAssertEqual(machine.states["EndCheckedIn"]?.type, "final")
    }

    // MARK: Cost on this device

    func testDeviceCost() async throws {
        let os = await MainActor.run { UIDevice.current.systemVersion }
        emit(["metric": "device", "model": machine(), "os": os, "simulator": isSimulator()])
        let specs = try packages()

        // Ed25519 verification alone (CryptoKit).
        let key = Curve25519.Signing.PrivateKey()
        let message = Data(repeating: 0x78, count: 3000)
        let signature = try key.signature(for: message)
        let verify = sample(2000, warmup: 100) { _ = key.publicKey.isValidSignature(signature, for: message) }
        emit(["metric": "ed25519Verify", "medianUs": verify.median, "p95Us": verify.p95])

        // One reported outcome in the wallet's driver: revalidation, transition, persistence.
        let (driver, store, suite) = isolatedDriver()
        defer { UserDefaults.standard.removePersistentDomain(forName: suite) }
        let hotel = specs.first { $0.name == "hotel-checkin" }!
        try store.install(hotel.jws, now: profile.clock)
        var stepSamples: [Double] = []
        var startSamples: [Double] = []
        for i in 0..<220 {
            let id = "cost-\(i)"
            var start = DispatchTime.now().uptimeNanoseconds
            driver.start(credentialId: id, packageId: "com.example.hotel.checkin", now: profile.clock)
            if i >= 20 { startSamples.append(Double(DispatchTime.now().uptimeNanoseconds - start) / 1000) }
            start = DispatchTime.now().uptimeNanoseconds
            driver.report(credentialId: id, handler: "PRESENT_CREDENTIAL", outcome: "success", now: profile.clock)
            if i >= 20 { stepSamples.append(Double(DispatchTime.now().uptimeNanoseconds - start) / 1000) }
            for _ in 0..<4 {
                start = DispatchTime.now().uptimeNanoseconds
                driver.confirm(credentialId: id, now: profile.clock)
                if i >= 20 { stepSamples.append(Double(DispatchTime.now().uptimeNanoseconds - start) / 1000) }
            }
            XCTAssertEqual(driver.run(for: id)?.ended, "success")
        }
        let step = stats(stepSamples), startCost = stats(startSamples)
        // The parts of a step: re-reading and re-validating the package from the store, and persisting the run record.
        let revalidate = sample(500, warmup: 50) {
            _ = try? store.package(id: "com.example.hotel.checkin", version: 3, now: self.profile.clock)
        }
        let record = GloveboxProcessDriver.Run(packageId: "com.example.hotel.checkin", version: 3, state: "PayCityTax")
        let persist = sample(500, warmup: 50) { driver.persistForMeasurement(record, for: "cost-persist") }
        let readRecord = sample(500, warmup: 50) { _ = driver.run(for: "cost-persist") }
        emit(["metric": "driverStep", "medianUs": step.median, "p95Us": step.p95, "stdUs": step.std, "samples": stepSamples.count,
              "startMedianUs": startCost.median, "startP95Us": startCost.p95,
              "revalidateMedianUs": revalidate.median, "persistMedianUs": persist.median,
              "readRecordMedianUs": readRecord.median])

        for spec in specs {
            let data = Data(spec.jws.utf8)
            let validation = sample(1000, warmup: 50) { _ = try? Validator.validate(data, profile: self.profile) }

            let store = isolatedStore()
            let install = sample(300, warmup: 20) { _ = try? store.install(spec.jws, now: self.profile.clock) }

            // Pure runtime cost per transition, without handler work.
            let validated = try Validator.validate(data, profile: profile)
            let runtime = GloveboxRuntime(validated: validated, profile: profile)
            let success = spec.paths.first { $0.terminal.hasPrefix("End") && self.isSuccess(spec, $0) } ?? spec.paths[0]
            let transitions = success.steps.count
            let advance = sample(2000, warmup: 100) {
                var state = runtime.initial
                for (from, outcome) in success.steps {
                    state = runtime.advance(from: from, outcome: outcome).next ?? state
                }
            }

            // Whole success path through the async interpreter with instant scripted handlers.
            let script = Dictionary(uniqueKeysWithValues: success.steps)
            var runSamples: [Double] = []
            for i in 0..<520 {
                let start = DispatchTime.now().uptimeNanoseconds
                _ = await runtime.run { state, _ in script[state] ?? "missing" }
                if i >= 20 { runSamples.append(Double(DispatchTime.now().uptimeNanoseconds - start) / 1000) }
            }
            let run = stats(runSamples)

            emit(["metric": "package", "name": spec.name, "states": spec.states, "jwsBytes": data.count,
                  "validateMedianUs": validation.median, "validateP95Us": validation.p95, "validateStdUs": validation.std,
                  "installMedianUs": install.median, "installP95Us": install.p95, "installStdUs": install.std,
                  "transitions": transitions,
                  "advancePerTransitionUs": advance.median / Double(max(transitions, 1)),
                  "runSuccessPathMedianUs": run.median, "runSuccessPathP95Us": run.p95, "runSuccessPathStdUs": run.std])
        }
    }

    // MARK: Scalability: validation cost against package size

    /// Packages far above the wallet's 64-state bound, validated with the bound lifted.
    func testValidationScalability() throws {
        let entries = try JSONSerialization.jsonObject(with: resource("glovebox_stress_vectors")) as? [[String: Any]] ?? []
        let stressProfile = try WalletProfile(json: resource("glovebox_stress_profile"))
        for entry in entries {
            guard let name = entry["id"] as? String, let states = entry["states"] as? Int,
                  let jws = entry["jws"] as? String else { continue }
            let raw = Data(jws.utf8)
            XCTAssertNoThrow(try Validator.validate(raw, profile: stressProfile), name)
            let repeats = states <= 128 ? 300 : 30
            let cost = sample(repeats, warmup: max(repeats / 10, 2)) { _ = try? Validator.validate(raw, profile: stressProfile) }
            emit(["metric": "stress", "name": name, "states": states, "jwsBytes": raw.count,
                  "validateMedianUs": cost.median, "validateP95Us": cost.p95, "validateStdUs": cost.std, "repeats": repeats])
        }
    }

    // MARK: Context: the credential operations that the handlers perform, on the same device

    /// Costs of the wallet's own credential operations, measured with the libraries the wallet
    /// uses: an ES256 signature (issuance proof and key-binding JWT), an SD-JWT presentation with
    /// key binding along the wallet's presentation path, and a BBS+ proof and its verification.
    func testCredentialOperationCost() async throws {
        let holder = P256.Signing.PrivateKey()
        let jwtPayload = Data(repeating: 0x41, count: 320)
        let es256 = sample(2000, warmup: 100) { _ = try? holder.signature(for: jwtPayload) }

        // SD-JWT credential with eight disclosable attributes, issued in the test.
        let attributes = ["given_name": "Alex", "family_name": "Example", "birthdate": "1990-01-01",
                          "reservation_id": "R-2026-0917", "hotel": "Example Hotel", "check_in": "2026-10-01",
                          "check_out": "2026-10-03", "room_type": "double"]
        let issuer = P256.Signing.PrivateKey()
        let credential = try await SDJWTIssuer.issue(issuersPrivateKey: issuer,
                                                    header: DefaultJWSHeaderImpl(algorithm: .ES256)) {
            ConstantClaims.iat(time: Date())
            ConstantClaims.exp(time: Date().addingTimeInterval(86_400))
            ConstantClaims.iss(domain: "https://issuer.example")
            ConstantClaims.sub(subject: "guest")
            FlatDisclosedClaim("given_name", attributes["given_name"]!)
            FlatDisclosedClaim("family_name", attributes["family_name"]!)
            FlatDisclosedClaim("birthdate", attributes["birthdate"]!)
            FlatDisclosedClaim("reservation_id", attributes["reservation_id"]!)
            FlatDisclosedClaim("hotel", attributes["hotel"]!)
            FlatDisclosedClaim("check_in", attributes["check_in"]!)
            FlatDisclosedClaim("check_out", attributes["check_out"]!)
            FlatDisclosedClaim("room_type", attributes["room_type"]!)
        }
        let serialised = CompactSerialiser(signedSDJWT: credential).serialised
        let reveal: Set<String> = ["given_name", "family_name", "reservation_id"]
        var presentSamples: [Double] = []
        for i in 0..<220 {
            let start = DispatchTime.now().uptimeNanoseconds
            let parsed = try CompactParser().getSignedSdJwt(serialisedString: serialised)
            let disclosures = parsed.disclosures.filter { disclosure in
                guard let data = Data(base64Encoded: disclosure.base64urlToBase64()),
                      let json = try? JSONSerialization.jsonObject(with: data) as? [Any], json.count == 3,
                      let key = json[1] as? String else { return false }
                return reveal.contains(key)
            }
            var kb: [String: Any] = ["aud": "https://verify.hotel.example", "nonce": "nonce-\(i)",
                                     "iat": Int(Date().timeIntervalSince1970)]
            let draft = try await SDJWTIssuer.presentation(
                holdersPrivateKey: holder, signedSDJWT: parsed, disclosuresToPresent: disclosures,
                keyBindingJWT: KBJWT(header: DefaultJWSHeaderImpl(algorithm: .ES256), kbJwtPayload: JSON(kb)))
            let draftSerialised = CompactSerialiser(signedSDJWT: draft).serialised
            let cut = draftSerialised.range(of: "~", options: String.CompareOptions.backwards)!.upperBound
            kb["sd_hash"] = Data(SHA256.hash(data: Data(String(draftSerialised[..<cut]).utf8))).base64URLEncodedString()
            let presentation = try await SDJWTIssuer.presentation(
                holdersPrivateKey: holder, signedSDJWT: parsed, disclosuresToPresent: disclosures,
                keyBindingJWT: KBJWT(header: DefaultJWSHeaderImpl(algorithm: .ES256), kbJwtPayload: JSON(kb)))
            let vpToken = CompactSerialiser(signedSDJWT: presentation).serialised
            if i >= 20 { presentSamples.append(Double(DispatchTime.now().uptimeNanoseconds - start) / 1000) }
            if i == 0 { XCTAssertEqual(disclosures.count, 3); XCTAssertFalse(vpToken.isEmpty) }
        }
        let sdjwtPresent = stats(presentSamples)

        // BBS+ credential with the same eight attributes, three revealed.
        let pair = GenerateKeyPair().generateKeyPair()
        let messages = attributes.keys.sorted().map { "\($0)=\(attributes[$0]!)" }
        let revealed: [UInt64] = [0, 1, 2]
        let bbsSign = sample(100, warmup: 5) {
            _ = SignRequest(messages: messages, dpubKeyBytes: pair.dpubKeyBytes, privKeyBytes: pair.privKeyBytes).signMessages()
        }
        let signed = SignRequest(messages: messages, dpubKeyBytes: pair.dpubKeyBytes, privKeyBytes: pair.privKeyBytes).signMessages()
        var proof = GenerateProofRequest(pubKeyBytes: pair.dpubKeyBytes, signatureBytes: signed.signature,
                                         revealedIndices: revealed, messages: messages).generateProof()
        let bbsProof = sample(100, warmup: 5) {
            proof = GenerateProofRequest(pubKeyBytes: pair.dpubKeyBytes, signatureBytes: signed.signature,
                                         revealedIndices: revealed, messages: messages).generateProof()
        }
        let disclosed = revealed.map { messages[Int($0)] }
        func verify() -> String {
            VerifyRequest(nonceBytes: proof.nonceBytes, proofRequestBytes: proof.proofRequestBytes,
                          proofBytes: proof.proofBytes, disclosedMessages: disclosed,
                          dpubKeyBytes: pair.dpubKeyBytes, totalMessageCount: UInt64(messages.count)).isValid()
        }
        let verdict = verify()
        XCTAssertEqual(verdict, "true", "BBS+ verification: \(verdict)")
        let bbsVerify = sample(100, warmup: 5) { _ = verify() }

        emit(["metric": "credentialOps", "attributes": attributes.count, "revealed": reveal.count,
              "es256SignMedianUs": es256.median, "es256SignP95Us": es256.p95, "es256SignStdUs": es256.std,
              "sdjwtPresentMedianUs": sdjwtPresent.median, "sdjwtPresentP95Us": sdjwtPresent.p95, "sdjwtPresentStdUs": sdjwtPresent.std,
              "sdjwtBytes": serialised.utf8.count,
              "bbsSignMedianUs": bbsSign.median, "bbsProofMedianUs": bbsProof.median, "bbsProofP95Us": bbsProof.p95, "bbsProofStdUs": bbsProof.std,
              "bbsVerifyMedianUs": bbsVerify.median, "bbsVerifyP95Us": bbsVerify.p95, "bbsVerifyStdUs": bbsVerify.std,
              "bbsProofBytes": proof.proofBytes.count])
    }

    // MARK: Baseline: the prototype engine's unprotected path

    /// What the prototype wallet did with a verifier response: decode and store the statechart, then
    /// jump to the named state with persistence. Measured with the prototype's own engine and its
    /// compiled hospitality statechart, console logging disabled.
    func testPrototypeEngineBaselineCost() throws {
        let json = String(decoding: try resource("glovebox_prototype_statechart"), as: UTF8.self)
        let engine = XStateEngine()
        let install = silencingStdout { sample(300, warmup: 20) { engine.updateMachine(json) } }
        let states = engine.getAllStateNames()
        XCTAssertGreaterThan(states.count, 3)
        var i = 0
        let step = silencingStdout {
            sample(1000, warmup: 50) {
                engine.forceState(credentialId: "baseline-cred", targetState: states[i % states.count])
                i += 1
            }
        }
        engine.deleteProcess(credentialId: "baseline-cred")
        UserDefaults.standard.removeObject(forKey: "dynamic_machine_json")
        emit(["metric": "prototypeEngine", "statechartBytes": json.utf8.count,
              "states": engine.machine?.states.count ?? 0,
              "installMedianUs": install.median, "installP95Us": install.p95, "installStdUs": install.std,
              "stepMedianUs": step.median, "stepP95Us": step.p95, "stepStdUs": step.std])
    }

    // MARK: Helpers

    private func isSuccess(_ spec: PackageSpec, _ path: PathSpec) -> Bool {
        guard let validated = try? Validator.validate(Data(spec.jws.utf8), profile: profile),
              let states = validated.package["states"]?.object else { return false }
        return states[path.terminal]?.object?["terminal"]?.string == "success"
    }

    private func sample(_ n: Int, warmup: Int, _ body: () -> Void) -> (median: Double, p95: Double, std: Double) {
        for _ in 0..<warmup { body() }
        var samples: [Double] = []
        samples.reserveCapacity(n)
        for _ in 0..<n {
            let start = DispatchTime.now().uptimeNanoseconds
            body()
            samples.append(Double(DispatchTime.now().uptimeNanoseconds - start) / 1000)
        }
        return stats(samples)
    }

    private func stats(_ samples: [Double]) -> (median: Double, p95: Double, std: Double) {
        let sorted = samples.sorted()
        guard !sorted.isEmpty else { return (0, 0, 0) }
        let mean = samples.reduce(0, +) / Double(samples.count)
        let variance = samples.reduce(0) { $0 + ($1 - mean) * ($1 - mean) } / Double(max(samples.count - 1, 1))
        return (sorted[sorted.count / 2], sorted[min(sorted.count - 1, Int(Double(sorted.count) * 0.95))], variance.squareRoot())
    }

    /// Runs `body` with stdout redirected to /dev/null, so console logging inside the measured code costs nothing.
    private func silencingStdout<T>(_ body: () -> T) -> T {
        fflush(stdout)
        let saved = dup(fileno(stdout))
        freopen("/dev/null", "a", stdout)
        defer { fflush(stdout); dup2(saved, fileno(stdout)); close(saved) }
        return body()
    }

    private func machine() -> String {
        if let simulated = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] { return simulated }
        var info = utsname()
        uname(&info)
        return withUnsafeBytes(of: &info.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    }

    private func isSimulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    /// Prints the metric and keeps it as a test attachment, so it survives in the result bundle.
    private func emit(_ fields: [String: Any]) {
        if let data = try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]),
           let line = String(data: data, encoding: .utf8) {
            print("GLOVEBOX_METRIC " + line)
            let attachment = XCTAttachment(string: "GLOVEBOX_METRIC " + line)
            attachment.name = "glovebox_metric_\(fields["metric"] ?? "")_\(fields["name"] ?? "")"
            attachment.lifetime = .keepAlways
            add(attachment)
        }
    }
}
