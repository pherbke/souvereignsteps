#!/usr/bin/env python3
"""Writes the test resources of the wallet's Glovebox test target from the artifact.

Usage:
  python3 wallet_resources.py <wallet>/PrototypeWalletTests/GloveboxResources [<wallet>/PrototypeWallet/domain/Glovebox]

The first directory receives the XCTest resources: the reference vectors
(`glovebox_vectors.json`), the five packages with their enumerated paths
(`glovebox_packages.json`), and the stress packages with the state bound lifted
(`glovebox_stress_vectors.json`, `glovebox_stress_profile.json`). The optional
second directory receives the wallet profile that the app bundles
(`glovebox_wallet_profile.json`). Run `run_evaluation.py` and
`bench_compilation.py` first.
"""

import json
import sys
from pathlib import Path

from glovebox.analysis import summarize
from glovebox.profile import WalletProfile

ROOT = Path(__file__).resolve().parent
MODELS = ["hotel-checkin", "hotel-checkout", "transit-ticket", "transit-inspection", "student-status"]


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    tests = Path(sys.argv[1])
    tests.mkdir(parents=True, exist_ok=True)
    profile_data = json.loads((ROOT / "profile" / "wallet_profile.json").read_text())
    profile = WalletProfile(profile_data)

    vectors = json.loads((ROOT / "vectors" / "vectors.json").read_text())
    (tests / "glovebox_vectors.json").write_text(json.dumps(vectors, indent=1) + "\n")

    packages = {}
    for name in MODELS:
        raw = (ROOT / "packages" / f"{name}.jws").read_bytes()
        package = json.loads((ROOT / "packages" / f"{name}.json").read_text())
        summary = summarize(package, profile, len(raw))
        packages[name] = {
            "jws": raw.decode(),
            "states": summary["states"],
            "transitions": summary["transitions"],
            "bytes": len(raw),
            "paths": [{"steps": p["steps"], "terminal": p["terminal"], "kind": p["kind"],
                       "remoteCount": p["remote"]} for p in summary["pathList"]],
        }
    (tests / "glovebox_packages.json").write_text(json.dumps(packages, indent=1) + "\n")

    compilation = json.loads((ROOT / "results" / "compilation.json").read_text())
    states = {w["workload"]: w["glovebox"]["states"] for w in compilation["workloads"]
              if not w["glovebox"]["rejected"]}
    stress = [dict(v, states=states[v["id"]])
              for v in json.loads((ROOT / "vectors" / "stress_vectors.json").read_text())]
    (tests / "glovebox_stress_vectors.json").write_text(json.dumps(stress) + "\n")
    (tests / "glovebox_stress_profile.json").write_text((ROOT / "profile" / "stress_profile.json").read_text())
    # The prototype compiler's hospitality statechart, for the prototype-engine baseline measurement.
    (tests / "glovebox_prototype_statechart.json").write_text(
        (ROOT / "models" / "legacy" / "hospitality.flow-walking-output.json").read_text())

    if len(sys.argv) > 2:
        app = Path(sys.argv[2])
        app.mkdir(parents=True, exist_ok=True)
        (app / "glovebox_wallet_profile.json").write_text(json.dumps(profile_data, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(vectors)} vectors, {len(packages)} packages "
          f"({sum(len(p['paths']) for p in packages.values())} paths), {len(stress)} stress packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
