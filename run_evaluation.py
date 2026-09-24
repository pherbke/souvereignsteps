#!/usr/bin/env python3
"""Reproduce every number reported in the paper.

    python3 run_evaluation.py            # writes results/, packages/, vectors/
    python3 run_evaluation.py --paper ../paper   # also regenerates LaTeX tables

The harness needs only the Python 3 standard library.
"""

import argparse
import copy
import json
import statistics
import sys
import time
from pathlib import Path

from glovebox import ed25519
from glovebox.analysis import enumerate_paths, summarize
from glovebox.canonical import b64url, canonical
from glovebox.compiler import CompileError, compile_bpmn
from glovebox.profile import WalletProfile, build_reference_profile_data, test_secret
from glovebox.publisher import sign_bytes, sign_package
from glovebox.runtime import checkpoint, resume, run
from glovebox.validator import PACKAGE_TYPE, Rejected, install, validate

ROOT = Path(__file__).resolve().parent
MODELS = ["hotel-checkin", "hotel-checkout", "transit-ticket", "transit-inspection", "student-status"]
LABELS = {
    "hotel-checkin": "Hotel check-in",
    "hotel-checkout": "Hotel checkout",
    "transit-ticket": "Transit ticket",
    "transit-inspection": "Ticket inspection",
    "student-status": "Student status",
}
PUBLISHER = {"com.example.hotel.": "hotel-2026", "org.example.transit.": "transit-2026",
             "edu.example.univ.": "univ-2026"}


def publisher_for(package_id):
    return next(kid for prefix, kid in PUBLISHER.items() if package_id.startswith(prefix))


def median_ms(fn, repeats):
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------

def build_packages(profile, out):
    packages = {}
    for name in MODELS:
        source = (ROOT / "models" / f"{name}.bpmn").read_bytes()
        package, report = compile_bpmn(source, profile)
        raw = sign_package(package, publisher_for(package["id"]))
        validated = validate(raw, profile)
        (out / f"{name}.json").write_text(json.dumps(package, indent=2, sort_keys=True) + "\n")
        (out / f"{name}.jws").write_bytes(raw)
        summary = summarize(package, profile, len(raw))
        summary["payloadBytes"] = len(canonical(package))
        summary["bpmnBytes"] = len(source)
        summary["compileReport"] = report
        summary["digest"] = validated.digest
        packages[name] = {"package": package, "raw": raw, "summary": summary, "source": source}
    return packages


# ---------------------------------------------------------------------------
# Adversarial package mutations (validator)
# ---------------------------------------------------------------------------

def _resign(package, kid="hotel-2026"):
    return sign_package(package, kid)


def adversarial_cases(base, profile):
    """Return (id, group, requirement, description, expected, raw, profile, preinstall)."""
    pkg = base["package"]
    raw = base["raw"]
    cases = []

    def add(cid, group, req, desc, expected, data, prof=None, pre=()):
        cases.append((cid, group, req, desc, expected, data, prof or profile, list(pre)))

    # Authenticity -------------------------------------------------------------
    head, body, sig = raw.decode().split(".")
    tampered = copy.deepcopy(pkg)
    tampered["states"]["PresentCheckIn"]["action"]["params"]["claims"].append("document_number")
    add("A1", "Authenticity", "R1", "payload modified after signing", "E_SIG_INVALID",
        f"{head}.{b64url(canonical(tampered))}.{sig}".encode())
    add("A2", "Authenticity", "R1", "signed with an untrusted key", "E_UNKNOWN_KEY",
        sign_bytes(canonical(pkg), "attacker-1"))
    forged = sign_bytes(canonical(pkg), "hotel-2026", secret=test_secret("attacker-1"))
    add("A3", "Authenticity", "R1", "trusted key id, forged signature", "E_SIG_INVALID", forged)
    add("A4", "Authenticity", "R1", "signature stripped", "E_SIG_MISSING", f"{head}.{body}.".encode())
    add("A5", "Authenticity", "R1", "trusted publisher signs a foreign namespace", "E_NAMESPACE",
        sign_package(pkg, "transit-2026"))

    # Lifecycle ----------------------------------------------------------------
    p = copy.deepcopy(pkg); p["schema"] = "glovebox/2"
    add("L1", "Lifecycle", "R5", "unsupported schema version", "E_SCHEMA", _resign(p))
    p = copy.deepcopy(pkg); p["notAfter"] = "2026-09-30T23:59:59Z"
    add("L2", "Lifecycle", "R5", "expired package", "E_EXPIRED", _resign(p))
    p = copy.deepcopy(pkg); p["version"] = 1; p["floor"] = 1
    add("L3", "Lifecycle", "R5", "replayed version below the floor", "E_ROLLBACK", _resign(p))
    forced = copy.deepcopy(pkg); forced["version"] = 4; forced["floor"] = 4
    add("L4", "Lifecycle", "R5", "superseded version after a forced update", "E_ROLLBACK", raw,
        pre=[_resign(forced)])

    # Structure ----------------------------------------------------------------
    # A duplicate state key: a last-key-wins parser would silently run the second
    # definition, which skips the payment step.
    text = canonical(pkg).decode()
    marker = '"PresentCheckIn":'  # the key that follows PayCityTax in canonical order
    duplicate_state = ('"PayCityTax":{"action":{"params":{"message":"Payment skipped"},'
                       '"type":"USER_NOTIFICATION"},"on":{"success":"RequestRoomKey"}},')
    dup_text = text.replace(marker, duplicate_state + marker, 1)
    assert dup_text.count('"PayCityTax":') == 2
    add("S1", "Structure", "R2", "duplicate state key (parser differential)", "E_DUPLICATE_KEY",
        sign_bytes(dup_text.encode(), "hotel-2026"))
    p = copy.deepcopy(pkg); p["initial"] = "Missing"
    add("S2", "Structure", "R2", "initial state does not exist", "E_BAD_INITIAL", _resign(p))
    p = copy.deepcopy(pkg); p["states"]["ConfirmCityTax"]["on"]["success"] = "Missing"
    add("S3", "Structure", "R2", "dangling transition", "E_DANGLING", _resign(p))
    p = copy.deepcopy(pkg); p["states"]["Orphan"] = {"terminal": "success"}
    add("S4", "Structure", "R2", "unreachable state", "E_UNREACHABLE", _resign(p))
    p = copy.deepcopy(pkg); p["states"]["PayCityTax"]["on"]["failure"] = "ConfirmCityTax"
    add("S5", "Structure", "R2", "retry loop around a payment", "E_CYCLE", _resign(p))

    # Typing -------------------------------------------------------------------
    p = copy.deepcopy(pkg); p["states"]["ConfirmCityTax"]["on"]["maybe"] = "PayCityTax"
    add("T1", "Typing", "R2", "transition on an undeclared outcome", "E_UNDECLARED_OUTCOME", _resign(p))
    p = copy.deepcopy(pkg); del p["states"]["RequestRoomKey"]["action"]["params"]["credentialType"]
    add("T2", "Typing", "R2", "missing required parameter", "E_PARAM", _resign(p))

    # Capability and policy ----------------------------------------------------
    p = copy.deepcopy(pkg)
    p["states"]["ActivateRemote"]["on"]["success"] = "UnlockDoor"
    p["states"]["UnlockDoor"] = {"action": {"type": "UNLOCK_BLE", "params": {"door": "204"}},
                                 "on": {"success": "EndCheckedIn"}}
    add("C1", "Capability", "R2", "action type without native handler", "E_UNKNOWN_ACTION", _resign(p))
    p = copy.deepcopy(pkg)
    p["states"]["ActivateRemote"]["on"]["success"] = "RevokeGuest"
    p["states"]["RevokeGuest"] = {"action": {"type": "REVOKE_CREDENTIAL", "params": {
        "credentialType": "IdentityVC", "endpointUrl": "https://keys.hotel.example/revoke"}},
        "on": {"success": "EndCheckedIn", "offline": "EndOffline"}}
    add("C2", "Capability", "R2", "installed handler outside the publisher's grant", "E_PUBLISHER_SCOPE",
        _resign(p))
    p = copy.deepcopy(pkg)
    p["states"]["PresentCheckIn"]["action"]["params"]["endpointUrl"] = "https://collector.tracker.example/in"
    add("C3", "Capability", "R4", "presentation to an unregistered origin", "E_ENDPOINT", _resign(p))
    p = copy.deepcopy(pkg); p["states"]["PresentCheckIn"]["action"]["params"]["claims"] = []
    add("C4", "Capability", "R4", "empty disclosure request", "E_EMPTY_DISCLOSURE", _resign(p))
    p = copy.deepcopy(pkg); del p["states"]["RequestRoomKey"]["on"]["offline"]
    add("C5", "Capability", "R6", "network step without offline outcome", "E_OFFLINE_UNMAPPED", _resign(p))
    p = copy.deepcopy(pkg)
    prev = "ActivateRemote"
    for i in range(60):
        sid = f"Info{i:02d}"
        p["states"][prev]["on"]["success"] = sid
        p["states"][sid] = {"action": {"type": "LOG_EVENT", "params": {"eventMessage": "padding"}},
                            "on": {"success": "EndCheckedIn"}}
        prev = sid
    add("C6", "Capability", "R2", "state-count bound exceeded", "E_LIMITS", _resign(p))
    return cases


def run_adversarial(base, profile):
    results = []
    for cid, group, req, desc, expected, raw, prof, pre in adversarial_cases(base, profile):
        floors = {}
        for earlier in pre:
            install(earlier, prof, floors)
        try:
            validate(raw, prof, floors=floors)
            code = "ACCEPTED"
        except Rejected as exc:
            code = exc.code
        results.append({"id": cid, "group": group, "requirement": req, "case": desc,
                        "expected": expected, "observed": code, "asIntended": code == expected,
                        "raw": raw.decode(), "preinstall": [e.decode() for e in pre]})
    # The duplicate-key case: show that a lenient last-key-wins parser would accept it.
    dup = next(r for r in results if r["id"] == "S1")
    head, body, _ = dup["raw"].split(".")
    from glovebox.canonical import b64url_decode
    lenient = json.loads(b64url_decode(body))
    dup["lenientParserSees"] = lenient["states"]["PayCityTax"]["action"]["type"]
    return results


# ---------------------------------------------------------------------------
# Compile-time negative models (restricted compiler)
# ---------------------------------------------------------------------------

NEG_BASE = """<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
    xmlns:camunda="http://camunda.org/schema/1.0/bpmn"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" id="Defs" targetNamespace="urn:example:negative">
  <bpmn:process id="Negative" isExecutable="true">
    <bpmn:extensionElements><camunda:properties>
      <camunda:property name="packageId" value="edu.example.univ.negative"/>
      <camunda:property name="version" value="1"/>
      <camunda:property name="minVersion" value="1"/>
      <camunda:property name="notAfter" value="2027-09-30T23:59:59Z"/>
    </camunda:properties></bpmn:extensionElements>
    START
    <bpmn:sequenceFlow id="f0" sourceRef="Start" targetRef="Check"/>
    <bpmn:task id="Check"><bpmn:extensionElements><camunda:properties>
      CHECKPROPS
    </camunda:properties></bpmn:extensionElements></bpmn:task>
    <bpmn:sequenceFlow id="f1" sourceRef="Check" targetRef="Gw"/>
    <bpmn:GATEWAY id="Gw" default="f1b"/>
    <bpmn:sequenceFlow id="f1a" sourceRef="Gw" targetRef="Present">
      <bpmn:conditionExpression xsi:type="bpmn:tFormalExpression">CONDITION</bpmn:conditionExpression>
    </bpmn:sequenceFlow>
    <bpmn:sequenceFlow id="f1b" sourceRef="Gw" targetRef="DEFAULTTARGET"/>
    PRESENT
    <bpmn:sequenceFlow id="f2" sourceRef="Present" targetRef="EndOk"/>
    EXTRA
    <bpmn:endEvent id="EndOk"><bpmn:extensionElements><camunda:properties>
      <camunda:property name="result" value="success"/></camunda:properties></bpmn:extensionElements></bpmn:endEvent>
    <bpmn:endEvent id="EndDenied"><bpmn:extensionElements><camunda:properties>
      <camunda:property name="result" value="deny"/></camunda:properties></bpmn:extensionElements></bpmn:endEvent>
  </bpmn:process>
</bpmn:definitions>
"""

PRESENT_TASK = """<bpmn:task id="Present"><bpmn:extensionElements><camunda:properties>
      <camunda:property name="actionType" value="PRESENT_CREDENTIAL"/>
      <camunda:property name="presentationRequest" value="StudentVC"/>
      <camunda:property name="claims" value="studentStatus"/>
      <camunda:property name="channel" value="proximity"/>
      <camunda:property name="targetDevice" value="NFC"/>
    </camunda:properties></bpmn:extensionElements>LOOP</bpmn:task>"""

CHECK_PROPS = ('<camunda:property name="actionType" value="VERIFY_LOCAL_CREDENTIAL"/>'
               '<camunda:property name="credentialType" value="StudentVC"/>')


def negative_model(**overrides):
    parts = {
        "START": '<bpmn:startEvent id="Start"/>',
        "CHECKPROPS": CHECK_PROPS,
        "GATEWAY": "exclusiveGateway",
        "CONDITION": "${outcome == 'success'}",
        "DEFAULTTARGET": "EndDenied",
        "PRESENT": PRESENT_TASK.replace("LOOP", ""),
        "EXTRA": "",
    }
    parts.update(overrides)
    text = NEG_BASE
    for key in ["START", "CHECKPROPS", "GATEWAY", "CONDITION", "DEFAULTTARGET", "PRESENT", "EXTRA"]:
        text = text.replace(key, parts[key])
    return text


def negative_cases():
    remote_present = (PRESENT_TASK.replace("LOOP", "")
                      .replace('value="proximity"', 'value="remote"')
                      .replace('<camunda:property name="targetDevice" value="NFC"/>',
                               '<camunda:property name="endpointUrl" value="https://verify.univ.example/vp"/>'))
    return [
        ("N01", "script task", "E_UNSUPPORTED",
         dict(PRESENT='<bpmn:scriptTask id="Present" scriptFormat="javascript"><bpmn:script>'
                      'fetch("https://x.example")</bpmn:script></bpmn:scriptTask>')),
        ("N02", "parallel gateway", "E_UNSUPPORTED", dict(GATEWAY="parallelGateway")),
        ("N03", "inclusive gateway", "E_UNSUPPORTED", dict(GATEWAY="inclusiveGateway")),
        ("N04", "event subprocess", "E_UNSUPPORTED",
         dict(EXTRA='<bpmn:subProcess id="Esp" triggeredByEvent="true"><bpmn:startEvent id="EspStart">'
                    '<bpmn:messageEventDefinition/></bpmn:startEvent></bpmn:subProcess>')),
        ("N05", "boundary timer event", "E_UNSUPPORTED",
         dict(EXTRA='<bpmn:boundaryEvent id="Timeout" attachedToRef="Present">'
                    '<bpmn:timerEventDefinition/></bpmn:boundaryEvent>')),
        ("N06", "call activity", "E_UNSUPPORTED",
         dict(PRESENT='<bpmn:callActivity id="Present" calledElement="other"/>')),
        ("N07", "intermediate catch event", "E_UNSUPPORTED",
         dict(EXTRA='<bpmn:intermediateCatchEvent id="Wait"><bpmn:messageEventDefinition/>'
                    '</bpmn:intermediateCatchEvent>')),
        ("N08", "event-based gateway", "E_UNSUPPORTED",
         dict(EXTRA='<bpmn:eventBasedGateway id="Race"/>')),
        ("N09", "timer start event", "E_UNSUPPORTED",
         dict(START='<bpmn:startEvent id="Start"><bpmn:timerEventDefinition/></bpmn:startEvent>')),
        ("N10", "multi-instance loop marker", "E_UNSUPPORTED",
         dict(PRESENT=PRESENT_TASK.replace("LOOP", "<bpmn:multiInstanceLoopCharacteristics/>"))),
        ("N11", "task without wallet action", "E_UNBOUND_TASK",
         dict(CHECKPROPS='<camunda:property name="credentialType" value="StudentVC"/>')),
        ("N12", "free-form gateway condition", "E_CONDITION", dict(CONDITION="${age &gt; 18}")),
        ("N13", "branch on an undeclared outcome", "E_OUTCOME", dict(CONDITION="${outcome == 'maybe'}")),
        ("N14", "second start event", "E_START",
         dict(EXTRA='<bpmn:startEvent id="Start2"/><bpmn:sequenceFlow id="fs2" sourceRef="Start2" '
                    'targetRef="Present"/>')),
        ("N15", "unreachable task", "E_UNREACHABLE",
         dict(EXTRA='<bpmn:task id="Orphan"><bpmn:extensionElements><camunda:properties>'
                    '<camunda:property name="actionType" value="LOG_EVENT"/>'
                    '<camunda:property name="eventMessage" value="never"/></camunda:properties>'
                    '</bpmn:extensionElements></bpmn:task>'
                    '<bpmn:sequenceFlow id="fo" sourceRef="Orphan" targetRef="EndOk"/>')),
        ("N16", "retry loop", "E_CYCLE", dict(DEFAULTTARGET="Check")),
        ("N17", "action type unknown to the wallet", "E_CAPABILITY",
         dict(CHECKPROPS='<camunda:property name="actionType" value="BIOMETRIC_MATCH"/>')),
        ("N18", "network step without offline outcome", "E_OFFLINE_UNMAPPED", dict(PRESENT=remote_present)),
        ("N19", "parameter bound to a runtime expression", "E_PARAM",
         dict(CHECKPROPS='<camunda:property name="actionType" value="VERIFY_LOCAL_CREDENTIAL"/>'
                         '<camunda:property name="credentialType" value="context.requestedType"/>')),
    ]


def run_negative(profile, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    base, _ = compile_bpmn(negative_model(), profile)  # the unmodified base must compile
    results = []
    for cid, desc, expected, overrides in negative_cases():
        text = negative_model(**overrides)
        (out_dir / f"{cid}.bpmn").write_text(text)
        try:
            compile_bpmn(text.encode(), profile)
            codes, diags = ["COMPILED"], []
        except CompileError as exc:
            codes = exc.codes
            diags = [d.as_dict() for d in exc.diagnostics]
        results.append({"id": cid, "construct": desc, "expected": expected, "codes": codes,
                        "asIntended": expected in codes, "exclusive": codes == [expected],
                        "diagnostics": diags})
    return {"baseCompiles": bool(base), "cases": results}


# ---------------------------------------------------------------------------
# Legacy models exported by the prototype editor
# ---------------------------------------------------------------------------

def run_legacy(profile):
    legacy = ROOT / "models" / "legacy"
    out = {}
    for name, flow in [("hospitality", "hospitality.flow-walking-output.json"),
                       ("transit", "transit.flow-walking-output.json")]:
        source = (legacy / f"{name}-editor-export.bpmn").read_text()
        revocations = source.count('value="REVOKE_CREDENTIAL"')
        prior = json.loads((legacy / flow).read_text())
        prior_states = prior.get("states", {})
        emitted = sum(1 for s in prior_states.values()
                      if isinstance(s.get("entry"), dict) and s["entry"].get("type") == "revokeCredential")
        try:
            compile_bpmn(source.encode(), profile)
            diagnostics = []
        except CompileError as exc:
            diagnostics = [d.as_dict() for d in exc.diagnostics]
        out[name] = {
            "authoredRevocationTasks": revocations,
            "flowWalkingStates": len(prior_states),
            "flowWalkingRevocationStates": emitted,
            "restrictedDiagnostics": diagnostics,
            "restrictedRejects": bool(diagnostics),
        }
    return out


# ---------------------------------------------------------------------------
# Change locality
# ---------------------------------------------------------------------------

def _actions(pkg, atype):
    return [(sid, s) for sid, s in pkg["states"].items() if s.get("action", {}).get("type") == atype]


def _ensure_offline_terminal(pkg):
    for sid, s in pkg["states"].items():
        if s.get("terminal") == "error":
            return sid
    pkg["states"]["EndOffline"] = {"terminal": "error"}
    return "EndOffline"


def change_credential_type(pkg, name):
    types = set()
    for _, s in _actions(pkg, "VERIFY_LOCAL_CREDENTIAL"):
        types.add(s["action"]["params"]["credentialType"])
    if not types:
        for _, s in _actions(pkg, "PRESENT_CREDENTIAL"):
            types.update(s["action"]["params"]["presentationRequest"])
    target = sorted(types)[0]
    for s in pkg["states"].values():
        params = s.get("action", {}).get("params", {})
        if params.get("credentialType") == target:
            params["credentialType"] = target + "v2"
        if target in params.get("presentationRequest", []):
            params["presentationRequest"] = [t + "v2" if t == target else t
                                             for t in params["presentationRequest"]]
    return True


def change_claim_set(pkg, name):
    changed = False
    for _, s in _actions(pkg, "PRESENT_CREDENTIAL"):
        claims = s["action"]["params"]["claims"]
        if len(claims) > 1:
            s["action"]["params"]["claims"] = claims[:-1]
            changed = True
    return changed


def change_copy(pkg, name):
    changed = False
    for s in pkg["states"].values():
        params = s.get("action", {}).get("params", {})
        for key in ("message", "promptMessage"):
            if key in params:
                params[key] = params[key] + " (updated)"
                changed = True
    return changed


def change_expiry(pkg, name):
    pkg["notAfter"] = "2027-12-31T23:59:59Z"
    return True


def change_reorder(pkg, name):
    """Swap the initial action with its success successor."""
    a = pkg["initial"]
    b = pkg["states"][a]["on"].get("success")
    if b is None or "action" not in pkg["states"][b]:
        return False
    after_b = pkg["states"][b]["on"].get("success")
    if after_b is None:
        return False
    pkg["initial"] = b
    pkg["states"][b]["on"]["success"] = a
    pkg["states"][a]["on"]["success"] = after_b
    return True


def change_insert_local(pkg, name):
    pkg["states"]["Intro"] = {
        "action": {"type": "USER_NOTIFICATION",
                   "params": {"message": "This service will ask for one credential.", "alertType": "INFO"}},
        "on": {"success": pkg["initial"]},
    }
    pkg["initial"] = "Intro"
    return True


def change_to_remote(pkg, name):
    urls = {"org.example.transit.": "https://tickets.transit.example/verify",
            "edu.example.univ.": "https://verify.univ.example/vp"}
    changed = False
    for _, s in _actions(pkg, "PRESENT_CREDENTIAL"):
        params = s["action"]["params"]
        if params["channel"] == "proximity":
            params["channel"] = "remote"
            params.pop("targetDevice", None)
            params["endpointUrl"] = next(u for p, u in urls.items() if pkg["id"].startswith(p))
            s["on"]["offline"] = _ensure_offline_terminal(pkg)
            changed = True
    return changed


def change_remove_module(pkg, name):
    """Remove the city-tax module (confirmation and payment) from the check-in."""
    states = pkg["states"]
    if "PayCityTax" not in states:
        return False
    states["PresentCheckIn"]["on"]["success"] = states["PayCityTax"]["on"]["success"]
    del states["ConfirmCityTax"], states["PayCityTax"]
    return True


NEW_CAPABILITY = {"locality": "local", "outcomes": ["success", "failure"],
                  "params": {"reason": {"type": "string", "required": True}}}


def change_new_capability(pkg, name):
    pkg["states"]["Biometric"] = {
        "action": {"type": "BIOMETRIC_MATCH", "params": {"reason": "Confirm it is you"}},
        "on": {"success": pkg["initial"], "failure": _first_deny(pkg)},
    }
    pkg["initial"] = "Biometric"
    return True


def _first_deny(pkg):
    return sorted(sid for sid, s in pkg["states"].items() if s.get("terminal") == "deny")[0]


CHANGES = [
    ("credential", "Required credential type", change_credential_type),
    ("claims", "Disclosed claim set (minimized)", change_claim_set),
    ("copy", "User-facing text", change_copy),
    ("expiry", "Expiry and version", change_expiry),
    ("reorder", "Reorder existing steps", change_reorder),
    ("insert", "Insert an existing local step", change_insert_local),
    ("module", "Remove the city-tax module", change_remove_module),
    ("remote", "Proximity to remote presentation", change_to_remote),
    ("capability", "New device capability", change_new_capability),
]


def run_changes(packages, profile):
    rows = []
    for key, label, fn in CHANGES:
        applied = accepted = client = offline_changed = 0
        details = []
        for name in MODELS:
            base = packages[name]
            pkg = copy.deepcopy(base["package"])
            if not fn(pkg, name):
                continue
            pkg["version"] += 1
            applied += 1
            raw = sign_package(pkg, publisher_for(pkg["id"]))
            before = base["summary"]
            try:
                validate(raw, profile)
                ok, code = True, "ACCEPTED"
            except Rejected as exc:
                ok, code = False, exc.code
            after = summarize(pkg, profile, len(raw)) if ok else None
            if ok:
                accepted += 1
                if (after["offlinePaths"], after["paths"]) != (before["offlinePaths"], before["paths"]) \
                        and after["offlinePaths"] != before["offlinePaths"]:
                    offline_changed += 1
            upgraded = profile.with_handler("BIOMETRIC_MATCH", NEW_CAPABILITY)
            if not ok:
                try:
                    validate(raw, upgraded)
                    client += 1
                except Rejected:
                    pass
            details.append({"model": name, "accepted": ok, "code": code,
                            "offlineBefore": f"{before['offlinePaths']}/{before['paths']}",
                            "offlineAfter": f"{after['offlinePaths']}/{after['paths']}" if after else None})
        rows.append({"key": key, "change": label, "applied": applied, "packageOnly": accepted,
                     "acceptedAfterClientUpdate": client, "offlineChanged": offline_changed,
                     "details": details})
    return rows


# ---------------------------------------------------------------------------
# Runtime: path replay and fail-closed behavior
# ---------------------------------------------------------------------------

def run_runtime(packages, profile):
    replayed = agreed = 0
    for name in MODELS:
        pkg, raw = packages[name]["package"], packages[name]["raw"]
        validated = validate(raw, profile)
        for path in enumerate_paths(pkg):
            script = dict(path["steps"])

            def handler(sid, action, script=script):
                return script[sid]

            trace = run(validated, profile, handler)
            expected_remote = [sid for sid, _ in path["steps"]
                               if profile.locality(pkg["states"][sid]["action"]) == "network"]
            replayed += 1
            if trace.terminal == path["terminal"] and [r[0] for r in trace.remote] == expected_remote:
                agreed += 1

    checks = []
    hotel = validate(packages["hotel-checkin"]["raw"], profile)
    inspection = validate(packages["transit-inspection"]["raw"], profile)

    def forced(sid, action):
        # A verifier response that names a target state instead of an outcome,
        # as the prototype's check-in kiosk did.
        return "ActivateRemote" if sid == "PresentCheckIn" else "success"

    t = run(hotel, profile, forced)
    checks.append({"check": "verifier names a target state instead of an outcome",
                   "result": t.kind, "reason": t.reason,
                   "reachedProtectedState": any(s[0] == "ActivateRemote" for s in t.steps)})
    t = run(inspection, profile, lambda sid, a: "offline" if sid == "PresentProof" else "success")
    checks.append({"check": "declared but unmapped outcome", "result": t.kind, "reason": t.reason})

    record = checkpoint(hotel, "PayCityTax")
    raw = packages["hotel-checkin"]["raw"]
    ok = resume(record, raw, profile, lambda sid, a: "success")
    checks.append({"check": "resume under the same accepted version", "result": ok.kind,
                   "terminal": ok.terminal})
    t = resume(record, raw, profile, lambda s, a: "success", floors={"com.example.hotel.checkin": 4})
    checks.append({"check": "resume after a forced update raised the floor", "result": t.kind,
                   "reason": t.reason})
    t = resume(record, raw, profile.with_clock("2027-02-01T00:00:00Z"), lambda s, a: "success")
    checks.append({"check": "resume after package expiry", "result": t.kind, "reason": t.reason})
    return {"pathsReplayed": replayed, "pathsAgreeing": agreed, "failClosed": checks}


# ---------------------------------------------------------------------------
# Timing (reference Python implementation)
# ---------------------------------------------------------------------------

def spread_ms(fn, repeats):
    """Median and standard deviation of wall-clock milliseconds over `repeats` calls, after three untimed warm-up calls."""
    for _ in range(3):
        fn()
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples), (statistics.stdev(samples) if len(samples) > 1 else 0.0)


def run_timing(packages, profile, repeats):
    out = {}
    for name in MODELS:
        raw, source, pkg = packages[name]["raw"], packages[name]["source"], packages[name]["package"]
        kid = publisher_for(pkg["id"])
        compile_med, compile_std = spread_ms(lambda: compile_bpmn(source, profile), repeats)
        validate_med, validate_std = spread_ms(lambda: validate(raw, profile), repeats)
        sign_med, sign_std = spread_ms(lambda: sign_package(pkg, kid), max(20, repeats // 4))
        out[name] = {
            "compileMs": round(compile_med, 3), "compileStdMs": round(compile_std, 3),
            "validateMs": round(validate_med, 3), "validateStdMs": round(validate_std, 3),
            "signMs": round(sign_med, 3), "signStdMs": round(sign_std, 3),
        }
    pub = bytes.fromhex(profile.publishers["hotel-2026"]["publicKey"])
    msg = b"x" * 3000
    sig = ed25519.sign(test_secret("hotel-2026"), msg)
    out["ed25519VerifyMs"] = round(median_ms(lambda: ed25519.verify(pub, msg, sig), repeats), 3)
    return out


# ---------------------------------------------------------------------------
# LaTeX output
# ---------------------------------------------------------------------------

def fmt_int(n):
    return f"{n:,}".replace(",", "{,}")


def write_tables(paper, packages, adversarial, negative, legacy, changes, runtime, swift, timing):
    tables = paper / "tables"
    tables.mkdir(parents=True, exist_ok=True)

    rows = []
    for name in MODELS:
        s = packages[name]["summary"]
        succ_remote = s["successPathRemote"][0]
        succ_actions = s["successPathActions"][0]
        rows.append(f"{LABELS[name]} & {s['states']} & {s['transitions']} & "
                    f"{s['localActions']}/{s['networkActions']} & {fmt_int(s['bytes'])} & "
                    f"{s['offlinePaths']}/{s['paths']} & {s['localFailurePaths']}/{s['failurePaths']} & "
                    f"{succ_remote}/{succ_actions} \\\\")
    (tables / "tab_packages.tex").write_text(
        "% Generated by artifact/run_evaluation.py -- do not edit by hand.\n"
        "\\begin{table}[t]\n\\centering\n\\footnotesize\n"
        "\\caption{Signed packages for the five processes. $L/N$: local/network actions; Bytes: compact JWS; "
        "Offline: paths without a network action; Private fail.: failure paths without a network action; "
        "Visible: remote-visible steps on the success path versus all its steps.}\n"
        "\\label{tab:packages}\n\\setlength{\\tabcolsep}{3.2pt}\n"
        "\\begin{tabular}{@{}lrrcrccc@{}}\n\\toprule\n"
        "Process & $|S|$ & $|T|$ & $L/N$ & Bytes & Offline & Private fail. & Visible \\\\\n\\midrule\n"
        + "\n".join(rows) +
        "\n\\bottomrule\n\\end{tabular}\n\\end{table}\n")

    groups = {}
    for r in adversarial:
        g = groups.setdefault(r["group"], {"cases": [], "req": set(), "ok": 0})
        g["cases"].append(r["case"])
        g["req"].add(r["requirement"])
        g["ok"] += r["asIntended"]
    short = {
        "payload modified after signing": "modified payload",
        "signed with an untrusted key": "untrusted key",
        "trusted key id, forged signature": "forged signature",
        "signature stripped": "stripped signature",
        "trusted publisher signs a foreign namespace": "foreign namespace",
        "unsupported schema version": "unsupported schema",
        "expired package": "expired",
        "replayed version below the floor": "rollback",
        "superseded version after a forced update": "superseded version",
        "installed handler outside the publisher's grant": "handler outside grant",
        "duplicate state key (parser differential)": "duplicate state key",
        "initial state does not exist": "bad initial state",
        "dangling transition": "dangling transition",
        "unreachable state": "unreachable state",
        "retry loop around a payment": "retry loop",
        "transition on an undeclared outcome": "undeclared outcome",
        "missing required parameter": "missing parameter",
        "action type without native handler": "unknown action",
        "presentation to an unregistered origin": "unregistered origin",
        "empty disclosure request": "empty disclosure",
        "network step without offline outcome": "unmapped offline",
        "state-count bound exceeded": "state bound",
    }
    lines = []
    for group in ["Authenticity", "Lifecycle", "Structure", "Typing", "Capability"]:
        g = groups[group]
        cases = ", ".join(short[c] for c in g["cases"])
        reqs = ", ".join(sorted(g["req"]))
        lines.append(f"{group} & {cases} & {reqs} & {g['ok']}/{len(g['cases'])} \\\\")
    total_ok = sum(r["asIntended"] for r in adversarial)
    neg_ok = sum(c["asIntended"] for c in negative["cases"])
    swift_line = ""  # the wallet validator's agreement is reported in the text
    (tables / "tab_adversarial.tex").write_text(
        "% Generated by artifact/run_evaluation.py -- do not edit by hand.\n"
        "\\begin{table}[t]\n\\centering\n\\footnotesize\n"
        "\\caption{Negative tests. Except for the authenticity cases, every mutation was re-signed "
        "with the legitimate publisher key. Rejected: the observed error code matched the intended~code.}\n"
        "\\label{tab:adversarial}\n\\setlength{\\tabcolsep}{3pt}\n"
        "\\begin{tabularx}{\\columnwidth}{@{}lXcr@{}}\n\\toprule\n"
        "Invariant & Mutations & Req. & Rejected \\\\\n\\midrule\n"
        + "\n".join(lines) +
        f"\n\\midrule\nTotal & {len(adversarial)} mutations of the signed package & & {total_ok}/{len(adversarial)} \\\\\n"
        + swift_line +
        f"Compiler & {len(negative['cases'])} models with one unsupported construct & R2, R6 & "
        f"{neg_ok}/{len(negative['cases'])} \\\\\n"
        "\\bottomrule\n\\end{tabularx}\n\\end{table}\n")

    lines = []
    for row in changes:
        if row["key"] == "capability":
            verdict = f"0/{row['applied']} (client update: {row['acceptedAfterClientUpdate']}/{row['applied']})"
        else:
            verdict = f"{row['packageOnly']}/{row['applied']}"
        lines.append(f"{row['change']} & {verdict} & {row['offlineChanged']} \\\\")
    (tables / "tab_changes.tex").write_text(
        "% Generated by artifact/run_evaluation.py -- do not edit by hand.\n"
        "\\begin{table}[t]\n\\centering\n\\footnotesize\n"
        "\\caption{Change locality: changed packages that the unchanged wallet accepted. Offline: "
        "packages whose number of offline paths changed.}\n"
        "\\label{tab:changes}\n\\setlength{\\tabcolsep}{3pt}\n"
        "\\begin{tabular}{@{}lcc@{}}\n\\toprule\n"
        "Change & Accepted without release & Offline \\\\\n\\midrule\n"
        + "\n".join(lines) +
        "\n\\bottomrule\n\\end{tabular}\n\\end{table}\n")

    write_registry_table(tables)
    write_compilation_table(paper, tables)

    total_paths = sum(packages[n]["summary"]["paths"] for n in MODELS)
    sizes = [packages[n]["summary"]["bytes"] for n in MODELS]
    payloads = [packages[n]["summary"]["payloadBytes"] for n in MODELS]
    local_rows = [r for r in changes if r["key"] != "capability"]
    compile_ms = [timing[n]["compileMs"] for n in MODELS]
    validate_ms = [timing[n]["validateMs"] for n in MODELS]
    exclusive = sum(c["exclusive"] for c in negative["cases"])
    macros = {
        "numAdv": len(adversarial),
        "numAdvOk": total_ok,
        "numNeg": len(negative["cases"]),
        "numNegOk": neg_ok,
        "numPaths": total_paths,
        "numPathsAgree": runtime["pathsAgreeing"],
        "minBytes": fmt_int(min(sizes)),
        "maxBytes": fmt_int(max(sizes)),
        "numChangeClasses": len(changes),
        "numChangePkgOnly": sum(1 for r in changes if r["packageOnly"] == r["applied"] and r["applied"]),
        "legacyTransitRevocations": legacy["transit"]["authoredRevocationTasks"],
        "legacyTransitStates": legacy["transit"]["flowWalkingStates"],
        "legacyTransitEmitted": legacy["transit"]["flowWalkingRevocationStates"],
        "numNegExclusive": exclusive,
        "minPayload": fmt_int(min(payloads)),
        "maxPayload": fmt_int(max(payloads)),
        "numChangeApplied": sum(r["applied"] for r in local_rows),
        "numChangeAccepted": sum(r["packageOnly"] for r in local_rows),
        "pyCompileMin": f"{min(compile_ms):.2f}",
        "pyCompileMax": f"{max(compile_ms):.2f}",
        "pySignMs": f"{statistics.median(timing[n]['signMs'] for n in MODELS):.1f}",
        "pyCompileCvMaxPercent": f"{100 * max(timing[n]['compileStdMs'] / timing[n]['compileMs'] for n in MODELS):.0f}",
        "pyValidateCvMaxPercent": f"{100 * max(max(timing[n]['validateStdMs'] / timing[n]['validateMs'], timing[n]['signStdMs'] / timing[n]['signMs']) for n in MODELS):.0f}",
        "pyValidateMs": f"{statistics.median(validate_ms):.1f}",
        "pyVerifyMs": f"{timing['ed25519VerifyMs']:.1f}",
    }
    if swift:
        macros.update({
            "swiftMinValidateUs": f"{min(swift['validateMedianMicros'].values()):.0f}",
            "swiftValidateUs": f"{swift['medianValidateUs']:.0f}",
            "swiftMaxValidateUs": f"{swift['maxMedianValidateUs']:.0f}",
            "swiftVerifyUs": f"{swift['medianVerifyUs']:.0f}",
            "swiftAgree": f"{swift['vectorsAgreeing']}/{swift['vectors']}",
            "swiftVectors": swift["vectors"],
            "swiftMachine": swift["machine"],
        })
    (paper / "sections" / "generated_numbers.tex").write_text(
        "% Generated by artifact/run_evaluation.py -- do not edit by hand.\n"
        + "".join(f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in macros.items()))


COMPILATION_ROWS = [
    ("hospitality export", "Hospitality export"),
    ("transit export", "Transit export"),
    ("linear 10 (notification)", "Linear, 10 tasks"),
    ("linear 100 (notification)", "Linear, 100 tasks"),
    ("linear 1000 (mixed)", "Linear, 1,000 tasks"),
    ("tree depth 2", "Tree, depth 2"),
    ("tree depth 5", "Tree, depth 5"),
    ("tree depth 10", "Tree, depth 10"),
]


def write_registry_table(tables):
    """The handler registry of the reference profile and the publishers' grants, from profile/wallet_profile.json."""
    data = json.loads((ROOT / "profile" / "wallet_profile.json").read_text())
    publishers = [("hotel-2026", "H"), ("transit-2026", "T"), ("univ-2026", "U")]
    order = ["VERIFY_LOCAL_CREDENTIAL", "REQUEST_USER_INPUT", "USER_NOTIFICATION", "LOG_EVENT",
             "ACTIVATE_REMOTE_CONTROL", "MANAGE_CREDENTIAL", "PRESENT_CREDENTIAL",
             "REQUEST_VC", "PROCESS_PAYMENT", "REVOKE_CREDENTIAL"]
    assert set(order) == set(data["handlers"]), sorted(data["handlers"])
    rows = []
    for name in order:
        h = data["handlers"][name]
        loc = h["locality"]
        loc = "L/N" if isinstance(loc, dict) else {"local": "L", "network": "N"}[loc]
        outcomes = ", ".join(o[0] for o in h["outcomes"])
        params = []
        for pname, spec in sorted(h["params"].items()):
            kind = spec["type"] + (", disclosure" if spec.get("disclosure") else "")
            mark = "" if spec.get("required") else ("$^{\\dagger}$" if "requiredIf" in spec else "$^{*}$")
            params.append(f"\\code{{{pname}}}{mark}: {kind}")
        grants = " ".join(letter for pid, letter in publishers if name in data["publishers"][pid]["handlers"]) or "--"
        tex_name = "\\act{" + name.replace("_", "\\_\\allowbreak ") + "}"
        rows.append(f"{tex_name} & {loc} & {outcomes} & {'; '.join(params)} & {grants} \\\\")
    (tables / "tab_registry.tex").write_text(
        "% Generated by artifact/run_evaluation.py -- do not edit by hand.\n"
        "\\begin{table*}[t]\n\\centering\n\\footnotesize\n"
        "\\caption{Handler registry $H$ of the reference wallet profile and the grants $H_p$ of its three publishers. "
        "Locality: local (L), network (N), or chosen by the channel parameter (L/N). Outcomes: success (s), failure (f), "
        "offline (o). Parameters are typed literals; $^{*}$ optional, $^{\\dagger}$ required for one channel only; "
        "an \\emph{endpoint} must match an origin registered for the publisher, and a \\emph{disclosure} list must be non-empty. "
        "Grants: hotel (H), transit operator (T), university (U).}\n"
        "\\label{tab:registry}\n\\setlength{\\tabcolsep}{4pt}\n"
        "\\begin{tabularx}{\\textwidth}{@{}lccXl@{}}\n\\toprule\n"
        "Handler & Locality & Outcomes & Parameters & Grants \\\\\n\\midrule\n"
        + "\n".join(rows) +
        "\n\\bottomrule\n\\end{tabularx}\n\\end{table*}\n")


def write_compilation_table(paper, tables):
    """Table and macros from bench_compilation.py and the Swift stress run, if present."""
    comp_path = ROOT / "results" / "compilation.json"
    if not comp_path.exists():
        return
    comp = {w["workload"]: w for w in json.loads(comp_path.read_text())["workloads"]}
    cli = json.loads(comp_path.read_text())["cliMs"]
    stress_path = ROOT / "results" / "swift_stress.json"
    stress = json.loads(stress_path.read_text())["validateMedianMicros"] if stress_path.exists() else {}

    cvs = []
    for w in comp.values():
        if w["prototype"].get("totalStdMs") is not None:
            cvs.append(w["prototype"]["totalStdMs"] / w["prototype"]["totalMs"])
        if not w["glovebox"]["rejected"] and w["glovebox"].get("compileStdMs") is not None:
            cvs.append(w["glovebox"]["compileStdMs"] / w["glovebox"]["compileMs"])

    def kb(n):
        return f"{n / 1000:.1f}" if n < 100_000 else f"{n / 1000:.0f}"

    def ms(x):
        return f"{x:.2f}" if x < 10 else f"{x:.1f}"

    lines = []
    for key, label in COMPILATION_ROWS:
        w = comp[key]
        proto, gb = w["prototype"], w["glovebox"]
        nodes = fmt_int(w["bpmnNodes"])
        if gb["rejected"]:
            glove = f"\\multicolumn{{3}}{{c}}{{rejected, {gb['diagnostics']} diagnostics}}"
        else:
            swift_ms = ms(stress[key] / 1000) if key in stress else "--"
            glove = f"{ms(gb['compileMs'])} & {kb(gb['payloadBytes'])} & {swift_ms}"
        lines.append(f"{label} & {nodes} & {ms(proto['totalMs'])} & {kb(proto['outputBytes'])} & {glove} \\\\")
    (tables / "tab_compilation.tex").write_text(
        "% Generated by artifact/run_evaluation.py from results/compilation.json -- do not edit by hand.\n"
        "\\begin{table}[t]\n\\centering\n\\footnotesize\n"
        "\\caption{Compilation on the platform's evaluation workloads: in-process medians of the "
        "prototype compiler and the \\sysname compiler, output size in kB, and Swift validation of "
        "the signed package. We lifted the 64-state bound for the synthetic models.}\n"
        "\\label{tab:compilation}\n\\setlength{\\tabcolsep}{2.6pt}\n"
        "\\begin{tabular}{@{}lrrrrrr@{}}\n\\toprule\n"
        " & & \\multicolumn{2}{c}{Prototype} & \\multicolumn{3}{c}{\\sysname} \\\\\n"
        "\\cmidrule(lr){3-4}\\cmidrule(l){5-7}\n"
        "Workload & Nodes & ms & kB & ms & kB & check ms \\\\\n\\midrule\n"
        + "\n".join(lines) +
        "\n\\bottomrule\n\\end{tabular}\n\\end{table}\n")

    synthetic = [k for k, _ in COMPILATION_ROWS if not comp[k]["glovebox"]["rejected"]]
    speed = [1 - comp[k]["glovebox"]["compileMs"] / comp[k]["prototype"]["totalMs"] for k in synthetic]
    size = [comp[k]["prototype"]["outputBytes"] / comp[k]["glovebox"]["payloadBytes"] for k in synthetic]
    size_jws = [comp[k]["prototype"]["outputBytes"] / comp[k]["glovebox"]["jwsBytes"] for k in synthetic]
    hosp = comp["hospitality export"]
    tree = comp["tree depth 10"]
    macros = {
        "hospBpmnKB": f"{hosp['bpmnBytes'] / 1000:.1f}",
        "hospProtoKB": f"{hosp['prototype']['outputBytes'] / 1000:.1f}",
        "hospProtoMs": f"{hosp['prototype']['totalMs']:.2f}",
        "hospRejectMs": f"{hosp['glovebox']['rejectMs']:.2f}",
        "compSpeedMin": f"{100 * min(speed):.0f}",
        "compSpeedMax": f"{100 * max(speed):.0f}",
        "compSizeMin": f"{min(size):.1f}",
        "compSizeMax": f"{max(size):.1f}",
        "compSizeJwsMin": f"{min(size_jws):.1f}",
        "compSizeJwsMax": f"{max(size_jws):.1f}",
        "compCvMaxPercent": f"{100 * max(cvs):.0f}" if cvs else "--",
        "treeNodes": fmt_int(tree["bpmnNodes"]),
        "treeStates": fmt_int(tree["glovebox"]["states"]),
        "treeProtoMs": f"{tree['prototype']['totalMs']:.0f}",
        "treeGloveMs": f"{tree['glovebox']['compileMs']:.0f}",
        "cliHospMs": f"{cli['hospitality export']:.0f}",
        "cliStartMs": f"{cli['interpreter start and networkx import']:.0f}",
    }
    if "tree depth 10" in stress:
        macros["swiftTreeMs"] = f"{stress['tree depth 10'] / 1000:.0f}"
    (paper / "sections" / "generated_compilation.tex").write_text(
        "% Generated by artifact/run_evaluation.py -- do not edit by hand.\n"
        + "".join(f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in macros.items()))


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--paper", type=Path, default=None, help="regenerate LaTeX tables in this paper dir")
    parser.add_argument("--repeats", type=int, default=200)
    parser.add_argument("--tables-only", action="store_true",
                        help="rewrite the paper's tables and macros from results/ without re-running the harness")
    args = parser.parse_args()

    if args.tables_only:
        if not args.paper:
            parser.error("--tables-only needs --paper")
        load = lambda key: json.loads((ROOT / "results" / f"{key}.json").read_text())
        packages = {n: {"summary": s} for n, s in load("packages").items()}
        swift_path = ROOT / "results" / "swift.json"
        swift = json.loads(swift_path.read_text()) if swift_path.exists() else None
        write_tables(args.paper, packages, load("adversarial"), load("negative"), load("legacy"),
                     load("changes"), load("runtime"), swift, load("timingPython"))
        print("tables and macros rewritten from results/")
        return 0

    for sub in ["results", "packages", "vectors", "profile"]:
        (ROOT / sub).mkdir(exist_ok=True)
    data = build_reference_profile_data()
    data["publishers"]["univ-2026"]["origins"] = ["https://verify.univ.example"]
    (ROOT / "profile" / "wallet_profile.json").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    profile = WalletProfile(data)

    packages = build_packages(profile, ROOT / "packages")
    adversarial = run_adversarial(packages["hotel-checkin"], profile)
    negative = run_negative(profile, ROOT / "models" / "negative")
    legacy = run_legacy(profile)
    changes = run_changes(packages, profile)
    runtime = run_runtime(packages, profile)
    timing = run_timing(packages, profile, args.repeats)

    vectors = [{"id": r["id"], "expected": r["expected"], "jws": r["raw"], "preinstall": r["preinstall"]}
               for r in adversarial]
    vectors += [{"id": f"OK-{n}", "expected": "ACCEPTED", "jws": packages[n]["raw"].decode()} for n in MODELS]
    (ROOT / "vectors" / "vectors.json").write_text(json.dumps(vectors, indent=2) + "\n")

    results = {
        "packages": {n: packages[n]["summary"] for n in MODELS},
        "adversarial": [{k: v for k, v in r.items() if k != "raw"} for r in adversarial],
        "negative": negative,
        "legacy": legacy,
        "changes": changes,
        "runtime": runtime,
        "timingPython": timing,
    }
    for key, value in results.items():
        (ROOT / "results" / f"{key}.json").write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    swift_path = ROOT / "results" / "swift.json"
    swift = json.loads(swift_path.read_text()) if swift_path.exists() else None
    if args.paper:
        write_tables(args.paper, packages, adversarial, negative, legacy, changes, runtime, swift, timing)

    print("packages:")
    for n in MODELS:
        s = packages[n]["summary"]
        print(f"  {n:20s} S={s['states']:2d} T={s['transitions']:2d} L/N={s['localActions']}/{s['networkActions']} "
              f"jws={s['bytes']}B payload={s['payloadBytes']}B offline={s['offlinePaths']}/{s['paths']} "
              f"privateFail={s['localFailurePaths']}/{s['failurePaths']} "
              f"succ={s['successPathRemote']}/{s['successPathActions']}")
    print(f"adversarial: {sum(r['asIntended'] for r in adversarial)}/{len(adversarial)} as intended")
    for r in adversarial:
        if not r["asIntended"]:
            print("   MISMATCH", r["id"], r["expected"], r["observed"])
    print(f"  duplicate-key vector, lenient parser sees PayCityTax as: {next(r for r in adversarial if r["id"] == "S1")['lenientParserSees']}")
    ok = sum(c["asIntended"] for c in negative["cases"])
    excl = sum(c["exclusive"] for c in negative["cases"])
    print(f"negative models: {ok}/{len(negative['cases'])} intended, {excl} exclusive")
    for c in negative["cases"]:
        if not c["exclusive"]:
            print("   ", c["id"], c["expected"], c["codes"])
    for name, info in legacy.items():
        print(f"legacy {name}: revocation tasks={info['authoredRevocationTasks']} flow-walking states="
              f"{info['flowWalkingStates']} revocation states={info['flowWalkingRevocationStates']} "
              f"restricted diagnostics={[d['message'] for d in info['restrictedDiagnostics']]}")
    print("changes:")
    for row in changes:
        print(f"  {row['change']:34s} applied={row['applied']} packageOnly={row['packageOnly']} "
              f"afterClientUpdate={row['acceptedAfterClientUpdate']} offlineChanged={row['offlineChanged']}")
    print(f"runtime: {runtime['pathsAgreeing']}/{runtime['pathsReplayed']} paths agree")
    for c in runtime["failClosed"]:
        print("  ", c)
    print("timing (python, median ms):", json.dumps(timing))
    return 0


if __name__ == "__main__":
    sys.exit(main())
