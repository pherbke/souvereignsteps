"""Package validation performed by the wallet before exposing any package UI.

A package travels as a compact JWS (RFC 7515) signed with EdDSA/Ed25519
(RFC 8037). The signature covers the exact payload bytes, so wallets written
in other languages need no shared canonicalization. The payload is parsed
strictly after the signature check: duplicate keys, floats, and non-finite
numbers are rejected.

Every rejection carries a stable error code so that the adversarial suite can
check that a mutation fails for the intended reason and not incidentally.
"""

import hashlib
import re
from urllib.parse import urlsplit

from . import ed25519
from .canonical import DuplicateKeyError, b64url_decode, strict_loads
from .profile import parse_time

TERMINAL_KINDS = ("success", "deny", "error")
PACKAGE_FIELDS = {"schema", "id", "version", "floor", "notAfter", "initial", "states"}
PACKAGE_TYPE = "glovebox-package+json"
DECIMAL_RE = re.compile(r"^[0-9]{1,6}(\.[0-9]{1,2})?$")


class Rejected(Exception):
    def __init__(self, code, detail):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class ValidatedPackage:
    def __init__(self, package, kid, digest, size):
        self.package = package
        self.kid = kid
        self.digest = digest
        self.size = size


def origin(url):
    """Return the https origin of a URL, or None if the URL is not acceptable."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        return None
    return f"https://{parts.hostname.lower()}" + (f":{port}" if port else "")


def endpoint_urls(package, profile):
    """All endpoint parameters of a package, as (state, parameter, url)."""
    found = []
    for sid, state in package["states"].items():
        if "action" not in state:
            continue
        spec = profile.handlers.get(state["action"].get("type"), {}).get("params", {})
        for name, value in state["action"].get("params", {}).items():
            if spec.get(name, {}).get("type") == "endpoint":
                found.append((sid, name, value))
    return found


def validate(raw, profile, now=None, floors=None):
    """Validate a serialized package; return a ValidatedPackage or raise Rejected.

    floors maps package identifiers to the highest floor this wallet has accepted
    (see install); without it, only the profile's configured floors apply.
    """
    now = now or profile.clock
    limits = profile.limits
    if len(raw) > limits["maxPackageBytes"]:
        raise Rejected("E_LIMITS", f"{len(raw)} bytes exceed the package size bound")

    # 1. Envelope: compact JWS with a protected header naming the publisher key.
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise Rejected("E_PARSE", "a compact JWS is ASCII") from None
    parts = text.split(".")
    if len(parts) == 2 or (len(parts) == 3 and parts[2] == ""):
        raise Rejected("E_SIG_MISSING", "package carries no signature")
    if len(parts) != 3:
        raise Rejected("E_PARSE", "a compact JWS has three segments")
    try:
        header = strict_loads(b64url_decode(parts[0]))
        payload_bytes = b64url_decode(parts[1])
        signature = b64url_decode(parts[2])
    except (ValueError, UnicodeDecodeError) as exc:
        raise Rejected("E_PARSE", f"malformed JWS segment: {exc}") from None
    if not isinstance(header, dict) or header.get("typ") != PACKAGE_TYPE:
        raise Rejected("E_PARSE", "protected header must declare the package type")

    # 2. Authenticity: trusted key and a valid signature over the exact bytes.
    if header.get("alg") != "EdDSA":
        raise Rejected("E_SIG_INVALID", "only EdDSA (Ed25519) is accepted")
    kid = header.get("kid")
    if kid not in profile.publishers:
        raise Rejected("E_UNKNOWN_KEY", f"publisher key {kid!r} is not trusted")
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    if not ed25519.verify(profile.public_key(kid), signing_input, signature):
        raise Rejected("E_SIG_INVALID", "signature does not verify")

    # 3. Strict payload parsing: parser differentials never reach later checks.
    try:
        package = strict_loads(payload_bytes)
    except DuplicateKeyError as exc:
        raise Rejected("E_DUPLICATE_KEY", f"duplicate JSON key {exc}") from None
    except (ValueError, UnicodeDecodeError) as exc:
        raise Rejected("E_PARSE", str(exc)) from None
    if not isinstance(package, dict):
        raise Rejected("E_PARSE", "payload must be a JSON object")

    # 4. Schema and namespace.
    if package.get("schema") not in profile.schemas:
        raise Rejected("E_SCHEMA", f"unsupported schema {package.get('schema')!r}")
    if set(package) != PACKAGE_FIELDS:
        raise Rejected("E_SCHEMA", "package fields do not match the schema")
    pid, version, pfloor = package["id"], package["version"], package["floor"]
    if not isinstance(pid, str) or any(isinstance(x, bool) or not isinstance(x, int) for x in (version, pfloor)):
        raise Rejected("E_SCHEMA", "malformed identifier, version, or floor")
    if not 1 <= pfloor <= version:
        raise Rejected("E_SCHEMA", "the floor must lie between 1 and the version")
    if version < 1 or not isinstance(package["states"], dict) or not isinstance(package["initial"], str):
        raise Rejected("E_SCHEMA", "malformed version, initial state, or state table")
    publisher = profile.publishers[kid]
    if not any(pid.startswith(ns) for ns in publisher["namespaces"]):
        raise Rejected("E_NAMESPACE", f"{kid} may not publish {pid}")

    # 5. Lifecycle: expiry and per-process version floor.
    try:
        not_after = parse_time(package["notAfter"])
    except ValueError:
        raise Rejected("E_SCHEMA", "malformed expiry") from None
    if now > not_after:
        raise Rejected("E_EXPIRED", f"package expired at {package['notAfter']}")
    floor = max(profile.version_floors.get(pid, 1), (floors or {}).get(pid, 1))
    if version < floor:
        raise Rejected("E_ROLLBACK", f"version {version} is below the floor {floor}")

    states = package["states"]
    if len(states) > limits["maxStates"]:
        raise Rejected("E_LIMITS", f"{len(states)} states exceed the state bound")

    # 6. Graph integrity: initial state, targets, reachability, acyclicity.
    _check_graph(package)

    # 7. Typing, capability confinement, disclosure, endpoints, offline outcomes.
    for sid, state in states.items():
        if "terminal" in state:
            continue
        action = state["action"]
        atype = action.get("type")
        if atype not in profile.handlers:
            raise Rejected("E_UNKNOWN_ACTION", f"{sid}: no native handler for {atype!r}")
        if atype not in publisher.get("handlers", []):
            raise Rejected("E_PUBLISHER_SCOPE", f"{sid}: {kid} is not granted {atype}")
        if set(action) - {"type", "params"}:
            raise Rejected("E_SCHEMA", f"{sid}: unexpected action members")
        _check_params(sid, atype, action.get("params", {}), profile, publisher)
        declared = profile.outcomes(atype)
        for outcome in state["on"]:
            if outcome not in declared:
                raise Rejected("E_UNDECLARED_OUTCOME", f"{sid}: {atype} never returns {outcome!r}")
        if profile.locality(action) == "network" and "offline" not in state["on"]:
            raise Rejected("E_OFFLINE_UNMAPPED", f"{sid}: network action lacks an offline transition")

    digest = hashlib.sha256(payload_bytes).hexdigest()
    return ValidatedPackage(package, kid, digest, len(raw))


def install(raw, profile, floors, now=None):
    """Validate against the wallet's stored floors, then ratchet the floor.

    The floor travels inside the signed payload, so only the publisher that may
    publish the package identifier can raise it. A wallet keeps the highest floor
    it has accepted; a forced update is a package whose floor equals its version.
    """
    validated = validate(raw, profile, now=now, floors=floors)
    pid = validated.package["id"]
    floors[pid] = max(floors.get(pid, 1), validated.package["floor"])
    return validated


def _check_graph(package):
    states = package["states"]
    initial = package["initial"]
    if initial not in states or not isinstance(states[initial], dict) or "terminal" in states[initial]:
        raise Rejected("E_BAD_INITIAL", f"initial state {initial!r} is missing or terminal")
    for sid, state in states.items():
        if not isinstance(state, dict):
            raise Rejected("E_SCHEMA", f"state {sid} is not an object")
        if "terminal" in state:
            if set(state) != {"terminal"} or state["terminal"] not in TERMINAL_KINDS:
                raise Rejected("E_TERMINAL", f"malformed terminal state {sid}")
            continue
        if set(state) != {"action", "on"} or not isinstance(state["action"], dict):
            raise Rejected("E_SCHEMA", f"malformed state {sid}")
        if not isinstance(state["on"], dict) or not state["on"]:
            raise Rejected("E_DANGLING", f"state {sid} has no outgoing transition")
        for outcome, target in state["on"].items():
            if target not in states:
                raise Rejected("E_DANGLING", f"{sid}.{outcome} targets missing state {target!r}")

    reached, frontier = {initial}, [initial]
    while frontier:
        sid = frontier.pop()
        for target in states[sid].get("on", {}).values():
            if target not in reached:
                reached.add(target)
                frontier.append(target)
    unreachable = sorted(set(states) - reached)
    if unreachable:
        raise Rejected("E_UNREACHABLE", f"unreachable states {unreachable}")

    back_edge = find_back_edge(initial, lambda sid: states[sid].get("on", {}).values())
    if back_edge:
        raise Rejected("E_CYCLE", f"cycle through {back_edge[0]} -> {back_edge[1]}")


def find_back_edges(initial, successors, first_only=False):
    """Iterative depth-first search; returns the back edges (cycles) reachable from initial."""
    colour = {initial: "grey"}
    stack = [(initial, iter(list(successors(initial))))]
    found = []
    while stack:
        node, pending = stack[-1]
        target = next(pending, None)
        if target is None:
            colour[node] = "black"
            stack.pop()
            continue
        state = colour.get(target)
        if state == "grey":
            found.append((node, target))
            if first_only:
                return found
        elif state is None:
            colour[target] = "grey"
            stack.append((target, iter(list(successors(target)))))
    return found


def find_back_edge(initial, successors):
    edges = find_back_edges(initial, successors, first_only=True)
    return edges[0] if edges else None


def _check_params(sid, atype, params, profile, publisher):
    spec = profile.handlers[atype]["params"]
    limits = profile.limits
    if not isinstance(params, dict):
        raise Rejected("E_PARAM", f"{sid}: parameters must be an object")
    unknown = sorted(set(params) - set(spec))
    if unknown:
        raise Rejected("E_PARAM", f"{sid}: unknown parameters {unknown}")
    for name, rule in spec.items():
        required = rule.get("required", False)
        condition = rule.get("requiredIf")
        if condition:
            required = all(params.get(key) == value for key, value in condition.items())
        if name not in params:
            if required:
                raise Rejected("E_PARAM", f"{sid}: missing parameter {name}")
            continue
        value = params[name]
        kind = rule["type"]
        if kind == "list":
            if not isinstance(value, list):
                raise Rejected("E_PARAM", f"{sid}: {name} must be a list")
            if rule.get("disclosure") and not value:
                raise Rejected("E_EMPTY_DISCLOSURE", f"{sid}: empty claim set")
            if not value or len(value) > limits["maxListLength"] or len(set(value)) != len(value):
                raise Rejected("E_PARAM", f"{sid}: {name} is empty, too long, or repeats items")
            if not all(isinstance(item, str) and item and len(item) <= limits["maxStringLength"]
                       for item in value):
                raise Rejected("E_PARAM", f"{sid}: {name} must contain bounded non-empty strings")
        elif kind == "enum":
            if value not in rule["values"]:
                raise Rejected("E_PARAM", f"{sid}: {name}={value!r} is not permitted")
        elif kind == "string":
            if not isinstance(value, str) or not value or len(value) > limits["maxStringLength"]:
                raise Rejected("E_PARAM", f"{sid}: {name} must be a bounded non-empty string")
        elif kind == "decimal":
            if not isinstance(value, str) or not DECIMAL_RE.match(value):
                raise Rejected("E_PARAM", f"{sid}: {name} must be a decimal amount")
        elif kind == "endpoint":
            if origin(value) not in publisher["origins"]:
                raise Rejected("E_ENDPOINT", f"{sid}: {name}={value!r} is not a registered origin")
        else:
            raise Rejected("E_PARAM", f"{sid}: unsupported parameter type {kind}")
