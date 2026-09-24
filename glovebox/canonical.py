"""Canonical JSON encoding and strict parsing.

Packages may contain only objects with ASCII keys, strings, safe integers,
booleans, null, and arrays. For these value types, compact JSON with sorted
keys coincides with the JSON Canonicalization Scheme (RFC 8785).

Parsing rejects duplicate object keys. JSON parsers disagree on duplicate-key
semantics (first wins, last wins, or error), so accepting duplicates would let
a validator and an interpreter see different state machines.
"""

import base64
import json

MAX_SAFE_INTEGER = 2**53 - 1


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a key."""


class NonCanonicalValueError(ValueError):
    """Raised when a value is outside the canonical package value types."""


def _reject_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateKeyError(key)
        obj[key] = value
    return obj


def _reject_constant(name):
    raise NonCanonicalValueError(f"non-finite number {name}")


def strict_loads(data):
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return json.loads(
        data,
        object_pairs_hook=_reject_duplicates,
        parse_constant=_reject_constant,
        parse_float=_reject_float,
    )


def _reject_float(text):
    raise NonCanonicalValueError(f"floating-point value {text}")


def _check(value):
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise NonCanonicalValueError("integer outside the safe range")
        return
    if isinstance(value, list):
        for item in value:
            _check(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise NonCanonicalValueError(f"non-ASCII or non-string key {key!r}")
            _check(item)
        return
    raise NonCanonicalValueError(f"unsupported type {type(value).__name__}")


def canonical(value):
    _check(value)
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    if not isinstance(text, str):
        raise ValueError("base64url value must be a string")
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))
