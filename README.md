# Sovereign Steps artifact

Reference implementation and evaluation harness for *Sovereign Steps: Process
Sovereignty for Mobile Identity Wallets* (anonymous SAC 2027 submission).
Every number, table, and generated LaTeX macro in the paper comes from this directory.

The measured artifact retains its original internal module, wire-format, result-field,
and wallet-integration identifiers. Renaming those identifiers would change signed
fixtures and break the direct link to the device measurements; they are compatibility
identifiers, not the paper or system name.

## Contents

| Path | What it is |
|---|---|
| `glovebox/` | Legacy internal module name for the restricted BPMN compiler, publisher (compact JWS, EdDSA), validator, bounded runtime, and path analysis. Python standard library only; `ed25519.py` follows RFC 8032. |
| `models/*.bpmn` | The five evaluated processes, in the prototype editor's export format (`camunda:property` entries with `actionType`). |
| `models/legacy/` | The prototype editor's original hospitality and transit exports (namespace anonymized) and the statecharts that the prototype's flow-walking compiler produced from them. |
| `models/negative/` | 19 generated models with one unsupported construct each (written by the evaluation script). |
| `profile/wallet_profile.json` | Reference wallet profile: handler registry, publishers, registered origins, version floors, limits, fixed clock. |
| `packages/` | Compiled packages (`.json`) and signed packages (`.jws`). |
| `vectors/vectors.json` | 22 adversarial package mutations (including a handler outside the publisher's grant and a rollback after a forced update) and the 5 valid packages, with expected error codes. |
| `swift/` | Swift validator (CryptoKit Ed25519, strict JSON parser), CLI, and `wallet-integration/`: the runtime, package store, process driver, wallet glue, XCTest suite, and diff as integrated into the prototype's iOS wallet (module name anonymized). The measured source keeps its legacy build identifiers. |
| `results/` | JSON results of the last run; `swift.json` holds the Swift CLI timings, `wallet_*.json` the measurements inside the iOS wallet (imported from XCTest result bundles by `import_wallet_metrics.py`; `wallet_ios.json` is the iPhone 13 Pro run used in the paper, `wallet_ios_run2.json` a repeat run, `wallet_sim.json` the simulator). |
| `bench_compilation.py` | Compilation benchmark on the platform's evaluation workloads (editor exports, linear chains, decision trees); writes `results/compilation.json` (including the revocation-fidelity models: k = 0–6 `REVOKE_CREDENTIAL` tasks on the sequence flow or in an event subprocess, compiled by both compilers) and the stress packages of 7–2,047 states for the validators (`vectors/stress_vectors.json`, `profile/stress_profile.json`). |
| `wallet_resources.py` | Writes the wallet test target's resources (vectors, packages with enumerated paths, stress packages, bundled profile) from the artifact. |
| `import_wallet_metrics.py` | Imports the legacy metric records of a wallet test run (`.xcresult`) into `results/wallet_<tag>.json` and the paper's wallet macros. |
| `make_plots.py` | Writes the paper's pgfplots figures (compilation and validation against size; one process step next to the credential operations) from `results/`. |
| `legacy_compiler/` | The prototype's flow-walking BPMN-to-XState compiler, unmodified, for the comparison (needs `networkx`). |
| `tests/` | Unit tests (RFC 8032 vectors, parsing, evaluation invariants, long-chain regression). |

## Reproduce

Requirements: Python 3.10+ (no packages). Optional: Swift 5.9+ with CryptoKit (macOS 13+).

```bash
python3 -m unittest discover -s tests          # 9 tests
python3 run_evaluation.py                       # regenerates packages/, vectors/, results/
python3 run_evaluation.py --paper ../paper      # also regenerates the paper's tables and macros
python3 run_evaluation.py --paper ../paper --tables-only   # tables and macros from results/ only, no re-measurement

cd swift && swift build -c release && cd ..
./swift/.build/release/glovebox-check profile/wallet_profile.json vectors/vectors.json 5000 > results/swift.json
python3 run_evaluation.py --paper ../paper      # picks up the Swift numbers

pip install networkx                            # only for the prototype compiler
python3 bench_compilation.py                    # compilation benchmark (compiler comparison in Section 7.5)
./swift/.build/release/glovebox-check profile/stress_profile.json vectors/stress_vectors.json 200 > results/swift_stress.json
python3 run_evaluation.py --paper ../paper      # regenerates the compilation macros

# inside the wallet (see swift/wallet-integration/README.md), then:
python3 import_wallet_metrics.py device.xcresult --tag ios --config Release --paper ../paper   # wallet macros
python3 make_plots.py --paper ../paper                                                          # Figures 3 and 4
```

Timings depend on the machine; the paper reports an Apple M2 Pro (macOS 26.6,
Python 3.14, Swift 6.3, release build), medians over 200 (Python) and 5,000 (Swift) runs
after untimed warm-up, with standard deviations stored next to every median
(`*StdMs`, `*StdUs`). The wallet numbers come from an iPhone 13 Pro (A15, iOS 26.6.2);
the prototype engine's own path (decode+store a statechart, forced state change) is measured
in the same test target as the baseline (`prototypeEngine` metric).

## Keys

Publisher keys are **test keys** derived deterministically from the key identifier
(`glovebox/profile.py: test_secret`, using the preserved internal module name). They make the signed packages reproducible and
must never protect anything real.

## Error codes

| Code | Meaning |
|---|---|
| `E_SIG_MISSING`, `E_SIG_INVALID`, `E_UNKNOWN_KEY`, `E_NAMESPACE` | authenticity |
| `E_SCHEMA`, `E_EXPIRED`, `E_ROLLBACK` | lifecycle |
| `E_DUPLICATE_KEY`, `E_PARSE`, `E_BAD_INITIAL`, `E_DANGLING`, `E_UNREACHABLE`, `E_CYCLE`, `E_TERMINAL` | structure |
| `E_UNDECLARED_OUTCOME`, `E_PARAM` | typing |
| `E_UNKNOWN_ACTION`, `E_ENDPOINT`, `E_EMPTY_DISCLOSURE`, `E_OFFLINE_UNMAPPED`, `E_LIMITS` | capability and policy |

Compiler diagnostics use `E_UNSUPPORTED`, `E_START`, `E_STRUCTURE`, `E_CONDITION`,
`E_UNBOUND_TASK`, `E_OUTCOME`, `E_CAPABILITY`, `E_PARAM`, `E_ENDPOINT`,
`E_OFFLINE_UNMAPPED`, `E_TERMINAL`, `E_UNREACHABLE`, `E_CYCLE`, and `E_PACKAGE`.
