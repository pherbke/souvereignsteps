# Wallet integration (iOS)

These are the Sovereign Steps files as integrated into the prototype's iOS wallet, with the
wallet's module name replaced by `PrototypeWallet` for anonymous review. The validator
and strict JSON parser are copied verbatim from the Swift package one level up. The
measured integration retains its original internal filenames, types, wire field, and
metric prefix so the published fixtures and device results remain reproducible; these
legacy identifiers are not the paper or system name.

| File | Role in the wallet |
|---|---|
| `GloveboxRuntime.swift` | Bounded interpreter: advances only on outcomes in the handler's alphabet that the package maps; no operation sets a state. |
| `GloveboxPackageStore.swift` | Installs packages: validates against the persisted floors, ratchets `floor[id] = max(floor[id], v_floor)`, keeps package bytes per version. |
| `GloveboxProcessDriver.swift` | Binds a credential's run to one package version, runs automatic local handlers, takes presentation outcomes from the wallet's presentation flow and confirmations from the process screen, re-validates the package before every step (expired or superseded packages stop the run fail-closed). |
| `GloveboxWallet.swift` | The install path for verifier responses (`glovebox_package` field) and the legacy switch (`glovebox.allowLegacyStatecharts`, off by default). |
| `glovebox_wallet_profile.json` | The wallet profile bundled with the app (same content as `../../profile/wallet_profile.json`). |
| `wallet_changes.diff` | The 44 changed lines in the wallet's existing files: the presentation outcome gains the package field, the two response handlers install packages instead of statecharts and no longer read the verifier's target state, the process screens' "next step" confirms the pending handler, and the engine gains a display-only method. |
| `Tests/GloveboxWalletTests.swift` | XCTest suite: reference vectors, path replay, fail-closed runtime, verifier-response handling, floor persistence across store restarts, the hotel check-in through the driver, validation of the stress packages (7–2,047 states), the wallet's own credential operations (ES256, SD-JWT presentation with key binding, BBS+ proof and verification), the cost measurements, and the prototype engine's own path as baseline (printed and attached as `GLOVEBOX_METRIC` lines, with standard deviations). The test target's resources come from `../../wallet_resources.py`. |

Run on a simulator or device from the wallet project:

```bash
xcodebuild test -scheme <wallet scheme> -configuration Release ENABLE_TESTABILITY=YES \
  -destination 'platform=iOS,id=<device>' -only-testing:<tests target>/GloveboxWalletTests \
  -resultBundlePath device.xcresult
python3 ../../import_wallet_metrics.py device.xcresult --tag ios --config Release --paper ../../../paper
python3 ../../make_plots.py --paper ../../../paper
```

Note: the wallet's BBS+ bindings (uniffi) must be generated with the same uniffi version as the compiled Rust library; a mismatch aborts the first BBS+ call with an API checksum error.
