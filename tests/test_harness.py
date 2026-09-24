"""Unit tests for the reference harness: python3 -m unittest discover -s tests"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import run_evaluation as ev  # noqa: E402
from glovebox import ed25519  # noqa: E402
from glovebox.canonical import DuplicateKeyError, strict_loads  # noqa: E402
from glovebox.profile import WalletProfile, build_reference_profile_data  # noqa: E402
from glovebox.validator import validate  # noqa: E402

RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
     "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08"
     "5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


def profile():
    data = build_reference_profile_data()
    data["publishers"]["univ-2026"]["origins"] = ["https://verify.univ.example"]
    return WalletProfile(data)


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for secret, public, message, signature in RFC8032:
            sk, msg = bytes.fromhex(secret), bytes.fromhex(message)
            self.assertEqual(ed25519.public_key(sk).hex(), public)
            self.assertEqual(ed25519.sign(sk, msg).hex(), signature)
            self.assertTrue(ed25519.verify(bytes.fromhex(public), msg, bytes.fromhex(signature)))
            self.assertFalse(ed25519.verify(bytes.fromhex(public), msg + b"!", bytes.fromhex(signature)))


class ParsingTests(unittest.TestCase):
    def test_duplicate_keys_rejected(self):
        with self.assertRaises(DuplicateKeyError):
            strict_loads(b'{"a":1,"a":2}')

    def test_floats_rejected(self):
        with self.assertRaises(ValueError):
            strict_loads(b'{"a":1.5}')


class EvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = profile()
        cls.packages = ev.build_packages(cls.profile, ROOT / "packages")

    def test_all_models_validate(self):
        for name in ev.MODELS:
            validate(self.packages[name]["raw"], self.profile)

    def test_adversarial_cases_fail_as_intended(self):
        for result in ev.run_adversarial(self.packages["hotel-checkin"], self.profile):
            self.assertTrue(result["asIntended"], result["id"])

    def test_negative_models_fail_as_intended(self):
        for case in ev.run_negative(self.profile, ROOT / "models" / "negative")["cases"]:
            self.assertTrue(case["asIntended"], case["id"])

    def test_legacy_models_rejected_by_restricted_compiler(self):
        legacy = ev.run_legacy(self.profile)
        self.assertTrue(all(info["restrictedRejects"] for info in legacy.values()))
        self.assertEqual(legacy["transit"]["flowWalkingRevocationStates"], 0)

    def test_long_chains_do_not_exhaust_the_stack(self):
        # Regression: recursive cycle detection crashed on 1,000-task chains.
        import bench_compilation as bench
        package, _ = ev.compile_bpmn(bench.linear(1500, "mixed").encode(), self.profile)
        self.assertEqual(len(package["states"]), 1501)

    def test_paths_replay_and_fail_closed(self):
        runtime = ev.run_runtime(self.packages, self.profile)
        self.assertEqual(runtime["pathsAgreeing"], runtime["pathsReplayed"])
        forced = runtime["failClosed"][0]
        self.assertEqual(forced["result"], "error")
        self.assertFalse(forced["reachedProtectedState"])


if __name__ == "__main__":
    unittest.main()
