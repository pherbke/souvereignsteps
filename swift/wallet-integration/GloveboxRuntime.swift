// Glovebox: bounded interpreter for validated process packages.
//
// The runtime resolves each state's action through the wallet's native handler
// registry and advances only on an outcome that the handler's alphabet declares
// and the package maps. Anything else ends the run in a fail-closed error. There
// is no operation that sets a state from outside: a verifier response influences
// a run only through the outcome of the handler that talks to that verifier.

import Foundation

struct GloveboxStep {
    let state: String
    let type: String
    let locality: String
    let outcome: String
}

struct GloveboxTrace {
    var terminal: String?
    var kind: String            // success | deny | error
    var steps: [GloveboxStep]
    var remote: [String]        // states whose action crossed the network
    var reason: String?
}

/// Native handler: receives the state name and the typed action, returns an outcome label.
typealias GloveboxHandler = (_ state: String, _ action: [String: JSONValue]) async -> String

struct GloveboxRuntime {
    let validated: ValidatedPackage
    let profile: WalletProfile

    private var states: [String: JSONValue] { validated.package["states"]?.object ?? [:] }
    var initial: String { validated.package["initial"]?.string ?? "" }

    /// The handler type a non-terminal state invokes.
    func actionType(of state: String) -> String? {
        states[state]?.object?["action"]?.object?["type"]?.string
    }

    /// One transition without executing the handler: the pure cost of the runtime.
    func advance(from state: String, outcome: String) -> (next: String?, reason: String?) {
        guard let node = states[state]?.object, let action = node["action"]?.object,
              let type = action["type"]?.string,
              let alphabet = profile.handlers[type]?.object?["outcomes"]?.array?.compactMap({ $0.string })
        else { return (nil, "E_NO_ACTION") }
        guard alphabet.contains(outcome) else { return (nil, "E_UNDECLARED_OUTCOME") }
        guard let target = node["on"]?.object?[outcome]?.string else { return (nil, "E_UNMAPPED_OUTCOME") }
        return (target, nil)
    }

    func run(from start: String? = nil, handler: GloveboxHandler) async -> GloveboxTrace {
        var trace = GloveboxTrace(terminal: nil, kind: "error", steps: [], remote: [], reason: nil)
        var current = start ?? initial
        // Acyclic packages end within |S| - 1 actions; the bound is a second line of defense.
        for _ in 0..<max(states.count, 1) {
            guard let node = states[current]?.object else {
                trace.reason = "E_MISSING_STATE"
                return trace
            }
            if let kind = node["terminal"]?.string {
                trace.terminal = current
                trace.kind = kind
                return trace
            }
            guard let action = node["action"]?.object, let type = action["type"]?.string else {
                trace.reason = "E_NO_ACTION"
                return trace
            }
            let locality = profile.locality(action) ?? "network"
            let outcome = await handler(current, action)
            trace.steps.append(GloveboxStep(state: current, type: type, locality: locality, outcome: outcome))
            if locality == "network" { trace.remote.append(current) }
            let (next, reason) = advance(from: current, outcome: outcome)
            guard let target = next else {
                trace.reason = reason
                return trace
            }
            current = target
        }
        trace.reason = "E_STEP_BOUND"
        return trace
    }
}
