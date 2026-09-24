// Glovebox: the wallet's install path for process logic received from verifiers.
//
// Before Glovebox, the wallet stored any `xstate_machine` contained in a verifier
// response and jumped to the state named in `process_step.id`. With Glovebox, a
// verifier response can deliver a signed package (`glovebox_package`), which the
// wallet installs only after validation, and a presentation influences a run only
// through the outcome of the presentation handler. Unsigned statecharts and forced
// target states are ignored unless legacy mode is switched on explicitly, which
// exists only to keep demonstrations with the old kiosks running.

import Foundation

enum GloveboxWallet {
    private static let legacyKey = "glovebox.allowLegacyStatecharts"

    /// Off by default: unsigned statecharts and forced states from verifiers are rejected.
    static var allowLegacyStatecharts: Bool {
        get { UserDefaults.standard.bool(forKey: legacyKey) }
        set { UserDefaults.standard.set(newValue, forKey: legacyKey) }
    }

    enum Decision: Equatable {
        case installed(packageId: String)
        case rejected(code: String)
        case legacyAccepted
        case legacyRejected
        case nothingDelivered
    }

    /// Decides what to do with the process-related fields of one verifier response.
    static func handle(packageJWS: String?, legacyStatechart: String?,
                       store: GloveboxPackageStore = .shared, now: Date = Date()) -> Decision {
        if let jws = packageJWS {
            do {
                let validated = try store.install(jws, now: now)
                return .installed(packageId: validated.package["id"]?.string ?? "")
            } catch let rejection as Rejection {
                print("[Glovebox] rejected package: \(rejection.code) \(rejection.detail)")
                return .rejected(code: rejection.code)
            } catch {
                return .rejected(code: "ERROR")
            }
        }
        if legacyStatechart != nil {
            if allowLegacyStatecharts { return .legacyAccepted }
            print("[Glovebox] ignored an unsigned statechart from a verifier response (legacy mode is off)")
            return .legacyRejected
        }
        return .nothingDelivered
    }

    /// Applies one verifier response to a credential's process: a delivered package is
    /// installed and its run started; a run already waiting on a presentation receives
    /// the presentation's outcome. The verifier's `process_step.id` is never consulted.
    @MainActor @discardableResult
    static func applyPresentation(_ outcome: PresentationOutcome, credentialId: String, engine: XStateEngine,
                                  driver: GloveboxProcessDriver = .shared) -> Decision {
        let wasActive = driver.isActive(credentialId)
        let decision = handle(packageJWS: outcome.gloveboxPackage, legacyStatechart: outcome.xstateMachineJson,
                              store: driver.store)
        switch decision {
        case .installed(let packageId):
            driver.start(credentialId: credentialId, packageId: packageId)
        case .legacyAccepted:
            if let chart = outcome.xstateMachineJson { engine.updateMachine(chart) }
        default:
            break
        }
        if wasActive {
            driver.report(credentialId: credentialId, handler: "PRESENT_CREDENTIAL",
                          outcome: outcome.accepted ? "success" : "failure")
        }
        driver.show(credentialId: credentialId, on: engine)
        return decision
    }

    /// A presentation that could not reach the verifier: the offline outcome of the handler.
    @MainActor
    static func presentationFailed(_ error: Error, credentialId: String, engine: XStateEngine,
                                   driver: GloveboxProcessDriver = .shared) {
        guard driver.isActive(credentialId) else { return }
        let outcome = (error as? URLError) != nil ? "offline" : "failure"
        driver.report(credentialId: credentialId, handler: "PRESENT_CREDENTIAL", outcome: outcome)
        driver.show(credentialId: credentialId, on: engine)
    }

    /// The "next step" control of the process screens: for a Glovebox run it confirms the
    /// pending user-confirmed action. Returns false when no run is active for the credential.
    @MainActor
    static func nextStep(credentialId: String, engine: XStateEngine,
                         driver: GloveboxProcessDriver = .shared) -> Bool {
        guard driver.isActive(credentialId) else { return false }
        driver.confirm(credentialId: credentialId)
        driver.show(credentialId: credentialId, on: engine)
        return true
    }
}
