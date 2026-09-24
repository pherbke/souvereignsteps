"""Bounded interpreter for validated packages.

The interpreter resolves each state's action through the fixed handler
registry, maps the returned outcome through the transition table, and fails
closed on outcomes that are undeclared or unmapped. It never evaluates
expressions from the package. Native handlers are simulated by a callback so
that every enumerated path can be replayed deterministically.
"""

from .validator import Rejected, validate


class Trace:
    def __init__(self, terminal, kind, steps, remote, reason=None):
        self.terminal = terminal
        self.kind = kind
        self.steps = steps
        self.remote = remote
        self.reason = reason

    def as_dict(self):
        return {
            "terminal": self.terminal,
            "kind": self.kind,
            "steps": self.steps,
            "remote": self.remote,
            "reason": self.reason,
        }


def run(validated, profile, handler, start=None):
    package = validated.package
    states = package["states"]
    sid = start or package["initial"]
    steps, remote = [], []
    # Acyclic graphs terminate within |S| - 1 actions; the bound is a second line of defense.
    for _ in range(len(states)):
        state = states[sid]
        if "terminal" in state:
            return Trace(sid, state["terminal"], steps, remote)
        action = state["action"]
        locality = profile.locality(action)
        outcome = handler(sid, action)
        steps.append((sid, action["type"], locality, outcome))
        if locality == "network":
            remote.append((sid, action["type"], action["params"].get("endpoint")))
        if outcome not in profile.outcomes(action["type"]):
            return Trace(None, "error", steps, remote, reason="E_UNDECLARED_OUTCOME")
        if outcome not in state["on"]:
            return Trace(None, "error", steps, remote, reason="E_UNMAPPED_OUTCOME")
        sid = state["on"][outcome]
    return Trace(None, "error", steps, remote, reason="E_STEP_BOUND")


def checkpoint(validated, state):
    """Coarse recovery record: no credentials, keys, or claim values."""
    package = validated.package
    return {
        "id": package["id"],
        "version": package["version"],
        "digest": validated.digest,
        "state": state,
    }


def resume(record, raw, profile, handler, floors=None):
    """Resume only if the cached package is still accepted and unchanged."""
    try:
        validated = validate(raw, profile, floors=floors)
    except Rejected as exc:
        return Trace(None, "error", [], [], reason="RESTART:" + exc.code)
    if validated.digest != record["digest"] or validated.package["version"] != record["version"]:
        return Trace(None, "error", [], [], reason="RESTART:E_VERSION_CHANGED")
    return run(validated, profile, handler, start=record["state"])
