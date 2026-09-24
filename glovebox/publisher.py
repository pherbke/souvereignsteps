"""Publisher-side signing of compiled packages as compact JWS (EdDSA)."""

from . import ed25519
from .canonical import b64url, canonical
from .profile import test_secret
from .validator import PACKAGE_TYPE


def sign_bytes(payload, kid, secret=None, header=None):
    """Sign exact payload bytes; return the compact JWS as ASCII bytes."""
    secret = secret if secret is not None else test_secret(kid)
    header = header or {"alg": "EdDSA", "kid": kid, "typ": PACKAGE_TYPE}
    head = b64url(canonical(header))
    body = b64url(payload)
    signature = ed25519.sign(secret, (head + "." + body).encode("ascii"))
    return (head + "." + body + "." + b64url(signature)).encode("ascii")


def sign_package(package, kid, secret=None):
    """Serialize a package canonically and sign it."""
    return sign_bytes(canonical(package), kid, secret)
