"""Wallet profile: the native handler registry H and local trust policy.

A profile describes what one wallet release can do (its reviewed native
handlers) and whom it trusts (publisher keys, namespaces, registered endpoint
origins, version floors). A process package can only select and parameterize
handlers listed here.

The handler names are the action vocabulary of the prototype platform (the
editor's ``actionType`` property). Glovebox adds three things to each entry:
a locality label, a finite outcome alphabet, and a typed parameter schema.
TRIGGER_WORKFLOW is deliberately absent: loading another flow is package
acquisition, which the wallet performs and validates outside any package.
"""

import datetime
import hashlib
from pathlib import Path

from . import SCHEMA, ed25519
from .canonical import strict_loads

NETWORK_OUTCOMES = ["success", "failure", "offline"]


def parse_time(text):
    if not isinstance(text, str) or not text.endswith("Z"):
        raise ValueError("timestamps must be UTC strings ending in 'Z'")
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


def test_secret(kid):
    """Deterministic *test-only* publisher key derived from the key identifier."""
    return hashlib.sha256(b"glovebox-test-key/" + kid.encode("utf-8")).digest()


class WalletProfile:
    def __init__(self, data):
        self.data = data
        self.name = data["profile"]
        self.schemas = set(data["schemas"])
        self.handlers = data["handlers"]
        self.publishers = data["publishers"]
        self.version_floors = dict(data.get("versionFloors", {}))
        self.limits = data["limits"]
        self.clock = parse_time(data["clock"])

    @classmethod
    def load(cls, path):
        return cls(strict_loads(Path(path).read_bytes()))

    def with_handler(self, name, spec):
        """Profile of a hypothetical client release that adds one native handler
        and grants it to every publisher."""
        data = dict(self.data)
        data["handlers"] = dict(self.handlers)
        data["handlers"][name] = spec
        data["publishers"] = {kid: dict(entry, handlers=sorted(set(entry.get("handlers", [])) | {name}))
                              for kid, entry in self.publishers.items()}
        data["profile"] = self.name + "+" + name
        return WalletProfile(data)

    def with_floor(self, package_id, floor):
        data = dict(self.data)
        data["versionFloors"] = dict(self.version_floors)
        data["versionFloors"][package_id] = floor
        return WalletProfile(data)

    def with_clock(self, clock):
        data = dict(self.data)
        data["clock"] = clock
        return WalletProfile(data)

    def public_key(self, kid):
        return bytes.fromhex(self.publishers[kid]["publicKey"])

    def locality(self, action):
        """Return 'local' or 'network' for a typed action instance."""
        spec = self.handlers[action["type"]]["locality"]
        if isinstance(spec, str):
            return spec
        value = action.get("params", {}).get(spec["byParam"])
        return spec["map"][value]

    def outcomes(self, action_type):
        return self.handlers[action_type]["outcomes"]


def _string(required=True):
    return {"type": "string", "required": required}


def _enum(values, required=True):
    return {"type": "enum", "values": values, "required": required}


def reference_handlers():
    """Typed version of the platform's action vocabulary (10 handler types)."""
    return {
        "VERIFY_LOCAL_CREDENTIAL": {
            "locality": "local",
            "outcomes": ["success", "failure"],
            "params": {
                "credentialType": _string(),
                "cacheOnly": _enum(["true", "false"], required=False),
            },
        },
        "USER_NOTIFICATION": {
            "locality": "local",
            "outcomes": ["success"],
            "params": {
                "message": _string(),
                "alertType": _enum(["INFO", "WARNING", "ERROR"], required=False),
            },
        },
        "REQUEST_USER_INPUT": {
            "locality": "local",
            "outcomes": ["success", "failure"],
            "params": {
                "formType": _enum(["CONSENT", "PAYMENT", "CONFIRM"]),
                "promptMessage": _string(),
            },
        },
        "LOG_EVENT": {
            "locality": "local",
            "outcomes": ["success"],
            "params": {
                "eventMessage": _string(),
                "status": _enum(["SUCCESS", "FAILURE"], required=False),
            },
        },
        "ACTIVATE_REMOTE_CONTROL": {
            "locality": "local",
            "outcomes": ["success", "failure"],
            "params": {
                "permissions": {"type": "list", "required": True},
                "roomId": _string(required=False),
            },
        },
        "MANAGE_CREDENTIAL": {
            "locality": "local",
            "outcomes": ["success", "failure"],
            "params": {
                "credentialType": _string(),
                "action": _enum(["ARCHIVE", "CLEAR"]),
            },
        },
        "PRESENT_CREDENTIAL": {
            "locality": {"byParam": "channel", "map": {"proximity": "local", "remote": "network"}},
            "outcomes": NETWORK_OUTCOMES,
            "params": {
                "presentationRequest": {"type": "list", "required": True},
                "claims": {"type": "list", "required": True, "disclosure": True},
                "channel": _enum(["proximity", "remote"]),
                "endpointUrl": {"type": "endpoint", "requiredIf": {"channel": "remote"}},
                "targetDevice": {
                    "type": "enum",
                    "values": ["NFC", "BLE", "QR"],
                    "requiredIf": {"channel": "proximity"},
                },
            },
        },
        "REQUEST_VC": {
            "locality": "network",
            "outcomes": NETWORK_OUTCOMES,
            "params": {
                "credentialType": _string(),
                "issuerId": _string(required=False),
                "credentialEndpointUrl": {"type": "endpoint", "required": True},
            },
        },
        "PROCESS_PAYMENT": {
            "locality": "network",
            "outcomes": NETWORK_OUTCOMES,
            "params": {
                "amount": {"type": "decimal", "required": True},
                "currency": _enum(["EUR", "USD"]),
                "merchantId": _string(),
                "paymentEndpointUrl": {"type": "endpoint", "required": True},
            },
        },
        "REVOKE_CREDENTIAL": {
            "locality": "network",
            "outcomes": NETWORK_OUTCOMES,
            "params": {
                "credentialType": _string(),
                "endpointUrl": {"type": "endpoint", "required": True},
            },
        },
    }


def build_reference_profile_data():
    """Return the reference wallet profile used by the evaluation."""
    publishers = {
        "hotel-2026": {
            "namespaces": ["com.example.hotel."],
            "handlers": ["VERIFY_LOCAL_CREDENTIAL", "USER_NOTIFICATION", "REQUEST_USER_INPUT",
                         "LOG_EVENT", "ACTIVATE_REMOTE_CONTROL", "MANAGE_CREDENTIAL",
                         "PRESENT_CREDENTIAL", "REQUEST_VC", "PROCESS_PAYMENT"],
            "origins": [
                "https://checkin.hotel.example",
                "https://checkout.hotel.example",
                "https://keys.hotel.example",
                "https://pay.hotel.example",
            ],
        },
        "transit-2026": {
            "namespaces": ["org.example.transit."],
            "handlers": ["VERIFY_LOCAL_CREDENTIAL", "USER_NOTIFICATION", "LOG_EVENT",
                         "PRESENT_CREDENTIAL", "REQUEST_VC"],
            "origins": ["https://tickets.transit.example"],
        },
        "univ-2026": {
            "namespaces": ["edu.example.univ."],
            "handlers": ["VERIFY_LOCAL_CREDENTIAL", "USER_NOTIFICATION", "REQUEST_USER_INPUT",
                         "LOG_EVENT", "PRESENT_CREDENTIAL"],
            "origins": [],
        },
    }
    for kid, entry in publishers.items():
        entry["publicKey"] = ed25519.public_key(test_secret(kid)).hex()
    return {
        "profile": "reference-wallet-2026.1",
        "schemas": [SCHEMA],
        "clock": "2026-10-01T12:00:00Z",
        "limits": {
            "maxPackageBytes": 16384,
            "maxStates": 64,
            "maxStringLength": 512,
            "maxListLength": 32,
        },
        "handlers": reference_handlers(),
        "publishers": publishers,
        "versionFloors": {
            "com.example.hotel.checkin": 2,
            "org.example.transit.inspection": 2,
        },
    }
