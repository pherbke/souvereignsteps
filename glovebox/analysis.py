"""Static analysis over validated packages.

Transition graphs are acyclic, so the set of start-to-terminal paths is finite
and can be enumerated exactly. A path is offline-executable when it contains
no network-requiring action. The remote-visible events of a path are its
network actions N(pi); under backend orchestration, every action outcome on
the path must reach the orchestrator so that it can select the next step.
"""


def enumerate_paths(package):
    states = package["states"]
    paths = []

    def walk(sid, steps):
        state = states[sid]
        if "terminal" in state:
            paths.append({"steps": steps, "terminal": sid, "kind": state["terminal"]})
            return
        for outcome, target in sorted(state["on"].items()):
            walk(target, steps + [(sid, outcome)])

    walk(package["initial"], [])
    return paths


def network_states(package, profile):
    return {
        sid for sid, state in package["states"].items()
        if "action" in state and profile.locality(state["action"]) == "network"
    }


def summarize(package, profile, size):
    states = package["states"]
    actions = {sid: s["action"] for sid, s in states.items() if "action" in s}
    network = network_states(package, profile)
    paths = enumerate_paths(package)

    def remote(path):
        return sum(1 for sid, _ in path["steps"] if sid in network)

    offline = [p for p in paths if remote(p) == 0]
    success = [p for p in paths if p["kind"] == "success"]
    failures = [p for p in paths if p["kind"] != "success"]
    fail_closed = {
        sid: [o for o in profile.outcomes(a["type"]) if o not in states[sid]["on"]]
        for sid, a in actions.items()
    }
    return {
        "id": package["id"],
        "version": package["version"],
        "states": len(states),
        "transitions": sum(len(s.get("on", {})) for s in states.values()),
        "actions": len(actions),
        "localActions": len(actions) - len(network),
        "networkActions": len(network),
        "terminals": sorted(sid for sid, s in states.items() if "terminal" in s),
        "bytes": size,
        "paths": len(paths),
        "offlinePaths": len(offline),
        "successPaths": len(success),
        "successPathActions": [len(p["steps"]) for p in success],
        "successPathRemote": [remote(p) for p in success],
        "failurePaths": len(failures),
        "localFailurePaths": sum(1 for p in failures if remote(p) == 0),
        "backendVisibleOutcomes": sum(len(p["steps"]) for p in paths),
        "remoteVisibleEvents": sum(remote(p) for p in paths),
        "failClosedOutcomes": {sid: o for sid, o in fail_closed.items() if o},
        "pathList": [
            {
                "terminal": p["terminal"],
                "kind": p["kind"],
                "steps": [f"{sid}:{outcome}" for sid, outcome in p["steps"]],
                "remote": remote(p),
            }
            for p in paths
        ],
    }
