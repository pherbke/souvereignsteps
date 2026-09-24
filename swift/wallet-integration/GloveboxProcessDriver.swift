// Glovebox: runs a credential's process through an installed package.
//
// A credential is bound to one version of a validated package, and its process
// advances only on the outcome of the native handler that ran for the current
// state. Before each step the cached package is validated again against the
// current floors and clock, so a run whose package expired or fell below a raised
// floor stops fail-closed before its next action; steps already taken are not
// undone. A newly installed version applies to runs started afterwards.
//
// Local handlers that need neither the user nor the network run automatically.
// Presentation outcomes come from the wallet's presentation flow. In this
// prototype, the remaining handlers (user input, payment, issuance, remote
// control, credential management) take their outcome from the user's
// confirmation in the process screen.

import Foundation

final class GloveboxProcessDriver {
    static let shared = GloveboxProcessDriver()

    struct Run: Codable, Equatable {
        let packageId: String
        let version: Int64
        var state: String
        var ended: String? = nil      // terminal kind, or the reason the run failed closed
    }

    enum Step: Equatable {
        case waiting(state: String, handler: String)
        case finished(state: String, kind: String)
        case failedClosed(state: String, reason: String)
        case ignored(state: String, reason: String)
    }

    typealias AutomaticHandler = (_ credentialId: String, _ action: [String: JSONValue]) -> String

    /// Handlers whose outcome the user supplies in the process screen in this prototype.
    static let userConfirmed: Set<String> = ["REQUEST_USER_INPUT", "PROCESS_PAYMENT", "REQUEST_VC",
                                             "ACTIVATE_REMOTE_CONTROL", "MANAGE_CREDENTIAL"]

    static let walletHandlers: [String: AutomaticHandler] = [
        "VERIFY_LOCAL_CREDENTIAL": { credentialId, _ in
            CardManager.shared.cards.contains { $0.id == credentialId } ? "success" : "failure"
        },
        "USER_NOTIFICATION": { _, action in
            print("[Glovebox] notification: \(action["params"]?.object?["message"]?.string ?? "")")
            return "success"
        },
        "LOG_EVENT": { _, action in
            print("[Glovebox] log: \(action["params"]?.object?["eventMessage"]?.string ?? "")")
            return "success"
        },
    ]

    let store: GloveboxPackageStore
    var automatic: [String: AutomaticHandler]
    private let defaults: UserDefaults
    private let runPrefix = "glovebox.run."

    init(store: GloveboxPackageStore = .shared, defaults: UserDefaults = .standard,
         automatic: [String: AutomaticHandler] = GloveboxProcessDriver.walletHandlers) {
        self.store = store
        self.defaults = defaults
        self.automatic = automatic
    }

    func run(for credentialId: String) -> Run? {
        guard let data = defaults.data(forKey: runPrefix + credentialId) else { return nil }
        return try? JSONDecoder().decode(Run.self, from: data)
    }

    /// A credential with an unfinished run advances only through this driver.
    func isActive(_ credentialId: String) -> Bool {
        run(for: credentialId).map { $0.ended == nil } ?? false
    }

    /// Starts a run of the latest installed version of a package, unless one is still active.
    @discardableResult
    func start(credentialId: String, packageId: String, now: Date = Date()) -> Step {
        if let current = run(for: credentialId), current.ended == nil {
            return .ignored(state: current.state, reason: "E_RUN_ACTIVE")
        }
        do {
            let validated = try store.package(id: packageId, now: now)
            let run = Run(packageId: packageId, version: validated.package["version"]?.int ?? 0,
                          state: validated.package["initial"]?.string ?? "")
            save(run, for: credentialId)
            return proceed(credentialId: credentialId, run: run, validated: validated)
        } catch {
            return .failedClosed(state: "", reason: (error as? Rejection)?.code ?? "ERROR")
        }
    }

    /// Reports the outcome of the native handler that ran for the credential's current state.
    /// An outcome from any other handler is ignored; one the package does not map ends the run.
    @discardableResult
    func report(credentialId: String, handler: String, outcome: String, now: Date = Date()) -> Step {
        guard var run = run(for: credentialId), run.ended == nil else {
            return .ignored(state: "", reason: "E_NO_RUN")
        }
        guard let validated = revalidate(&run, credentialId, now: now) else {
            return .failedClosed(state: run.state, reason: run.ended ?? "ERROR")
        }
        return advance(credentialId: credentialId, run: &run, validated: validated, handler: handler, outcome: outcome)
    }

    /// The user's confirmation in the process screen, for handlers that take their outcome from it.
    @discardableResult
    func confirm(credentialId: String, now: Date = Date()) -> Step {
        guard var run = run(for: credentialId), run.ended == nil else {
            return .ignored(state: "", reason: "E_NO_RUN")
        }
        guard let validated = revalidate(&run, credentialId, now: now) else {
            return .failedClosed(state: run.state, reason: run.ended ?? "ERROR")
        }
        let type = GloveboxRuntime(validated: validated, profile: store.profile).actionType(of: run.state) ?? ""
        guard Self.userConfirmed.contains(type) else {
            return .ignored(state: run.state, reason: "E_NOT_USER_CONFIRMED")
        }
        return advance(credentialId: credentialId, run: &run, validated: validated, handler: type, outcome: "success")
    }

    /// Re-validates the run's package against the current floors and clock; ends the run if it no longer validates.
    private func revalidate(_ run: inout Run, _ credentialId: String, now: Date) -> ValidatedPackage? {
        do {
            return try store.package(id: run.packageId, version: run.version, now: now)
        } catch {
            _ = end(&run, credentialId, failure: (error as? Rejection)?.code ?? "ERROR")
            return nil
        }
    }

    private func advance(credentialId: String, run: inout Run, validated: ValidatedPackage,
                         handler: String, outcome: String) -> Step {
        let runtime = GloveboxRuntime(validated: validated, profile: store.profile)
        guard runtime.actionType(of: run.state) == handler else {
            return .ignored(state: run.state, reason: "E_HANDLER_MISMATCH")
        }
        let (next, reason) = runtime.advance(from: run.state, outcome: outcome)
        guard let target = next else { return end(&run, credentialId, failure: reason ?? "ERROR") }
        run.state = target
        save(run, for: credentialId)
        return proceed(credentialId: credentialId, run: run, validated: validated)
    }

    /// Runs automatic handlers until a terminal state or a step that needs the user or the network.
    private func proceed(credentialId: String, run: Run, validated: ValidatedPackage) -> Step {
        var run = run
        let runtime = GloveboxRuntime(validated: validated, profile: store.profile)
        let states = validated.package["states"]?.object ?? [:]
        for _ in 0..<max(states.count, 1) {
            guard let node = states[run.state]?.object else { return end(&run, credentialId, failure: "E_MISSING_STATE") }
            if let kind = node["terminal"]?.string {
                run.ended = kind
                save(run, for: credentialId)
                return .finished(state: run.state, kind: kind)
            }
            guard let action = node["action"]?.object, let type = action["type"]?.string else {
                return end(&run, credentialId, failure: "E_NO_ACTION")
            }
            guard let handler = automatic[type] else { return .waiting(state: run.state, handler: type) }
            let (next, reason) = runtime.advance(from: run.state, outcome: handler(credentialId, action))
            guard let target = next else { return end(&run, credentialId, failure: reason ?? "ERROR") }
            run.state = target
            save(run, for: credentialId)
        }
        return end(&run, credentialId, failure: "E_STEP_BOUND")
    }

    private func end(_ run: inout Run, _ credentialId: String, failure reason: String) -> Step {
        run.ended = reason
        save(run, for: credentialId)
        print("[Glovebox] run for \(credentialId) failed closed in \(run.state): \(reason)")
        return .failedClosed(state: run.state, reason: reason)
    }

    private func save(_ run: Run, for credentialId: String) {
        defaults.set(try? JSONEncoder().encode(run), forKey: runPrefix + credentialId)
    }

    /// Exposes the persistence of one run record for the cost measurement in the test target.
    func persistForMeasurement(_ run: Run, for credentialId: String) {
        save(run, for: credentialId)
    }

    // MARK: Display

    /// Shows the run in the wallet's process screens. The statechart shown there is
    /// derived from the validated package; it is used for display only.
    func show(credentialId: String, on engine: XStateEngine, now: Date = Date()) {
        guard let run = run(for: credentialId),
              let validated = try? store.package(id: run.packageId, version: run.version, now: now),
              let chart = Self.displayStatechart(validated) else { return }
        engine.showGloveboxState(credentialId: credentialId, statechart: chart, state: run.state)
    }

    static func displayStatechart(_ validated: ValidatedPackage) -> String? {
        guard let pid = validated.package["id"]?.string, let version = validated.package["version"]?.int,
              let initial = validated.package["initial"]?.string,
              let states = validated.package["states"]?.object else { return nil }
        var nodes: [String: Any] = [:]
        for (sid, value) in states {
            guard let node = value.object else { continue }
            if let kind = node["terminal"]?.string {
                nodes[sid] = ["type": "final", "description": kind == "success" ? "Completed" : "Ended (\(kind))"]
                continue
            }
            let action = node["action"]?.object ?? [:]
            let type = action["type"]?.string ?? ""
            let params = action["params"]?.object ?? [:]
            let text = params["message"]?.string ?? params["promptMessage"]?.string ?? type
            var on: [String: String] = [:]
            for (outcome, target) in node["on"]?.object ?? [:] { on["\(type).\(outcome)"] = target.string }
            nodes[sid] = ["description": text, "on": on]
        }
        let chart: [String: Any] = ["id": "glovebox:\(pid)@\(version)", "initial": initial, "states": nodes]
        guard let data = try? JSONSerialization.data(withJSONObject: chart, options: [.sortedKeys]) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
