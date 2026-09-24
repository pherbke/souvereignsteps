#!/usr/bin/env python3
"""Compilation benchmark: prototype compiler versus the Glovebox compiler.

Workloads follow the prototype's own evaluation: the two editor exports
(hospitality and transit), linear chains of 10, 100, and 1,000 tasks
(notifications, presentations, and a mix), and nested decision trees of depth
2, 5, and 10. Synthetic models use plain BPMN tasks, exclusive gateways, and
labeled outcome branches, which both compilers accept.

    pip install networkx            # only needed for the prototype compiler
    python3 bench_compilation.py    # writes results/compilation.json

Times are in-process medians. The prototype compiler is timed stage by stage
(XML parsing, graph construction, compilation, JSON serialization); its
command-line tool additionally pays interpreter start-up and imports, which we
measure separately for two workloads.
"""

import contextlib
import io
import json
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from glovebox.canonical import canonical
from glovebox.compiler import CompileError, compile_bpmn
from glovebox.profile import WalletProfile, build_reference_profile_data
from glovebox.publisher import sign_package
from glovebox.validator import Rejected, validate

ROOT = Path(__file__).resolve().parent
LEGACY = ROOT / "legacy_compiler"

HEADER = """<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
    xmlns:camunda="http://camunda.org/schema/1.0/bpmn"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" id="Defs" targetNamespace="urn:example:bench">
<bpmn:process id="Bench" isExecutable="true">
<bpmn:extensionElements><camunda:properties>
<camunda:property name="packageId" value="edu.example.univ.bench"/>
<camunda:property name="version" value="1"/>
<camunda:property name="minVersion" value="1"/>
<camunda:property name="notAfter" value="2027-09-30T23:59:59Z"/>
</camunda:properties></bpmn:extensionElements>
"""
FOOTER = "</bpmn:process>\n</bpmn:definitions>\n"

ACTIONS = {
    "notification": [("actionType", "USER_NOTIFICATION"), ("message", "Please continue.")],
    "presentation": [("actionType", "PRESENT_CREDENTIAL"), ("presentationRequest", "StudentVC"),
                     ("claims", "studentStatus,validUntil"), ("channel", "proximity"),
                     ("targetDevice", "NFC")],
    "verify": [("actionType", "VERIFY_LOCAL_CREDENTIAL"), ("credentialType", "StudentVC")],
    "log": [("actionType", "LOG_EVENT"), ("eventMessage", "Step completed")],
}
MIX = ["verify", "notification", "presentation", "log"]
ACTIONS["revoke"] = [("actionType", "REVOKE_CREDENTIAL"), ("credentialType", "RoomKeyVC"),
                     ("endpointUrl", "https://verify.univ.example/revoke")]


def _task(tid, props):
    body = "".join(f'<camunda:property name="{k}" value="{v}"/>' for k, v in props)
    return (f'<bpmn:task id="{tid}"><bpmn:extensionElements><camunda:properties>{body}'
            f'</camunda:properties></bpmn:extensionElements></bpmn:task>\n')


def _end(eid, result):
    return (f'<bpmn:endEvent id="{eid}"><bpmn:extensionElements><camunda:properties>'
            f'<camunda:property name="result" value="{result}"/></camunda:properties>'
            f'</bpmn:extensionElements></bpmn:endEvent>\n')


def _flow(fid, source, target, outcome=None):
    if outcome is None:
        return f'<bpmn:sequenceFlow id="{fid}" sourceRef="{source}" targetRef="{target}"/>\n'
    return (f'<bpmn:sequenceFlow id="{fid}" name="{outcome}" sourceRef="{source}" targetRef="{target}">'
            f'<bpmn:conditionExpression xsi:type="bpmn:tFormalExpression">${{outcome == \'{outcome}\'}}'
            f'</bpmn:conditionExpression></bpmn:sequenceFlow>\n')


def linear(n, variant):
    parts = [HEADER, '<bpmn:startEvent id="Start"/>\n']
    prev = "Start"
    for i in range(1, n + 1):
        kind = MIX[(i - 1) % len(MIX)] if variant == "mixed" else variant
        parts.append(_task(f"T{i}", ACTIONS[kind]))
        parts.append(_flow(f"f{i}", prev, f"T{i}"))
        prev = f"T{i}"
    parts += [_end("End", "success"), _flow("fEnd", prev, "End"), FOOTER]
    return "".join(parts)


def tree(depth):
    """Full binary decision tree: 2^depth - 1 checks, each branching on success/failure."""
    internal = 2 ** depth - 1
    parts = [HEADER, '<bpmn:startEvent id="Start"/>\n', _flow("f0", "Start", "N1")]
    for i in range(1, internal + 1):
        parts.append(_task(f"N{i}", ACTIONS["verify"]))
        parts.append('<bpmn:exclusiveGateway id="G%d"/>\n' % i)
        parts.append(_flow(f"a{i}", f"N{i}", f"G{i}"))
        for j, outcome in ((2 * i, "success"), (2 * i + 1, "failure")):
            target = f"N{j}" if j <= internal else f"E{j}"
            if j > internal:
                parts.append(_end(target, "success" if j == 2 ** (depth + 1) - 2 else "deny"))
            parts.append(_flow(f"b{i}_{outcome}", f"G{i}", target, outcome))
    parts.append(FOOTER)
    return "".join(parts)


def fidelity(k, placement):
    """k REVOKE_CREDENTIAL tasks, either on the sequence flow (each with the offline branch that a
    network action needs) or inside an event subprocess, as the transit model authored them."""
    parts = [HEADER, '<bpmn:startEvent id="Start"/>\n', _task("Notify", ACTIONS["notification"]),
             _flow("f0", "Start", "Notify")]
    if placement == "flow":
        prev, outcome = "Notify", None
        for i in range(1, k + 1):
            parts += [_task(f"R{i}", ACTIONS["revoke"]), _flow(f"fr{i}", prev, f"R{i}", outcome),
                      f'<bpmn:exclusiveGateway id="G{i}"/>\n', _flow(f"fg{i}", f"R{i}", f"G{i}"),
                      _end(f"Off{i}", "error"), _flow(f"fo{i}", f"G{i}", f"Off{i}", "offline")]
            prev, outcome = f"G{i}", "success"
        parts += [_end("End", "success"), _flow("fEnd", prev, "End", outcome), FOOTER]
    else:
        parts += [_end("End", "success"), _flow("fEnd", "Notify", "End"),
                  '<bpmn:subProcess id="Esp" triggeredByEvent="true">\n',
                  '<bpmn:startEvent id="EspStart"><bpmn:messageEventDefinition/></bpmn:startEvent>\n']
        prev = "EspStart"
        for i in range(1, k + 1):
            parts += [_task(f"R{i}", ACTIONS["revoke"]), _flow(f"fr{i}", prev, f"R{i}")]
            prev = f"R{i}"
        parts += [_end("EspEnd", "success"), _flow("fEspEnd", prev, "EspEnd"), "</bpmn:subProcess>\n", FOOTER]
    return "".join(parts)


def fidelity_profile_data(data):
    """Reference profile with REVOKE_CREDENTIAL granted to the benchmark publisher."""
    fid = json.loads(json.dumps(data))
    pub = fid["publishers"]["univ-2026"]
    pub["handlers"] = sorted(set(pub.get("handlers", [])) | {"REVOKE_CREDENTIAL"})
    return fid


FLOW_NODES = {"startEvent", "endEvent", "task", "userTask", "serviceTask", "exclusiveGateway",
              "eventBasedGateway", "parallelGateway", "inclusiveGateway", "intermediateCatchEvent",
              "intermediateThrowEvent", "boundaryEvent", "subProcess", "callActivity", "scriptTask"}


def bpmn_nodes(text):
    """Count BPMN flow nodes, with or without a namespace prefix, including nested ones."""
    import xml.etree.ElementTree as ET
    return sum(1 for e in ET.fromstring(text.encode()).iter() if e.tag.rsplit("}", 1)[-1] in FLOW_NODES)


def median_ms(fn, repeats):
    for _ in range(3):  # untimed warm-up
        fn()
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


def legacy_modules():
    sys.path.insert(0, str(LEGACY))
    try:
        import compiler as legacy_compiler  # noqa: E402
        import graph as legacy_graph  # noqa: E402
        import parser as legacy_parser  # noqa: E402
    except ImportError as exc:  # networkx missing
        print(f"prototype compiler unavailable ({exc}); install networkx to include it")
        return None
    finally:
        sys.path.pop(0)
    return legacy_parser, legacy_graph, legacy_compiler


def bench_legacy(mods, path, repeats):
    parse, graph, comp = mods
    stages = {"parse": [], "graph": [], "compile": [], "serialize": []}
    output = None
    quiet = io.StringIO()  # the prototype compiler prints debug output
    for _ in range(3):  # untimed warm-up
        with contextlib.redirect_stdout(quiet):
            comp.compile_xstate(graph.build_bpmn_graph(parse.parse_xml(str(path))),
                                parse.parse_xml(str(path)).find(".//{http://www.omg.org/spec/BPMN/20100524/MODEL}process").attrib.get("id", "unknown"))
    for _ in range(repeats):
        t0 = time.perf_counter()
        root = parse.parse_xml(str(path))
        t1 = time.perf_counter()
        with contextlib.redirect_stdout(quiet):
            g = graph.build_bpmn_graph(root)
        t2 = time.perf_counter()
        process = root.find(".//{http://www.omg.org/spec/BPMN/20100524/MODEL}process")
        with contextlib.redirect_stdout(quiet):
            machine = comp.compile_xstate(g, process.attrib.get("id", "unknown"))
        t3 = time.perf_counter()
        output = json.dumps(machine, indent=2)
        t4 = time.perf_counter()
        for key, a, b in (("parse", t0, t1), ("graph", t1, t2), ("compile", t2, t3), ("serialize", t3, t4)):
            stages[key].append((b - a) * 1000)
    medians = {k: statistics.median(v) for k, v in stages.items()}
    totals = [sum(stages[k][i] for k in stages) for i in range(repeats)]
    states = json.loads(output).get("states", {})
    return {
        "totalMs": statistics.median(totals),
        "totalStdMs": statistics.stdev(totals) if len(totals) > 1 else 0.0,
        "stagesMs": medians,
        "outputBytes": len(output.encode()),
        "states": len(states),
        "revocationStates": sum(1 for s in states.values()
                                if isinstance(s.get("entry"), dict) and s["entry"].get("type") == "revokeCredential"),
    }


def bench_glovebox(source, profile, stress_profile, repeats):
    try:
        package, _ = compile_bpmn(source, profile)
    except CompileError as exc:
        return {"rejected": True, "diagnostics": len(exc.diagnostics),
                "rejectMs": median_ms(lambda: _reject(source, profile), repeats)}
    for _ in range(3):  # untimed warm-up
        canonical(compile_bpmn(source, profile)[0])
    compile_samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        canonical(compile_bpmn(source, profile)[0])
        compile_samples.append((time.perf_counter() - start) * 1000)
    compile_ms = statistics.median(compile_samples)
    compile_std = statistics.stdev(compile_samples) if len(compile_samples) > 1 else 0.0
    raw = sign_package(package, "univ-2026")
    within_bounds = True
    try:
        validate(raw, profile)
    except Rejected as exc:
        within_bounds = exc.code != "E_LIMITS"
    validate_ms = median_ms(lambda: validate(raw, stress_profile), max(5, repeats // 4))
    return {
        "rejected": False,
        "jws": raw.decode(),
        "compileMs": compile_ms,
        "compileStdMs": compile_std,
        "states": len(package["states"]),
        "payloadBytes": len(canonical(package)),
        "jwsBytes": len(raw),
        "withinWalletBounds": within_bounds,
        "validateMsPython": validate_ms,
    }


def _reject(source, profile):
    try:
        compile_bpmn(source, profile)
    except CompileError:
        pass


def cli_ms(path, repeats=10):
    """End-to-end command-line compilation, including interpreter start-up and imports."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.json"
        return median_ms(lambda: subprocess.run(
            [sys.executable, "main.py", str(path), str(out)], cwd=LEGACY,
            capture_output=True, check=True), repeats)


def main():
    data = build_reference_profile_data()
    data["publishers"]["univ-2026"]["origins"] = ["https://verify.univ.example"]
    profile = WalletProfile(data)
    stress = dict(data)
    stress["limits"] = dict(data["limits"], maxStates=100000, maxPackageBytes=50_000_000)
    stress_profile = WalletProfile(stress)

    workloads = [
        ("hospitality export", (ROOT / "models/legacy/hospitality-editor-export.bpmn").read_text(), 200),
        ("transit export", (ROOT / "models/legacy/transit-editor-export.bpmn").read_text(), 200),
        ("linear 10 (notification)", linear(10, "notification"), 200),
        ("linear 100 (notification)", linear(100, "notification"), 100),
        ("linear 1000 (notification)", linear(1000, "notification"), 30),
        ("linear 1000 (presentation)", linear(1000, "presentation"), 30),
        ("linear 1000 (mixed)", linear(1000, "mixed"), 30),
        ("tree depth 2", tree(2), 200),
        ("tree depth 5", tree(5), 100),
        ("tree depth 10", tree(10), 20),
    ]
    mods = legacy_modules()
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, text, repeats in workloads:
            path = Path(tmp) / (name.replace(" ", "_").replace("(", "").replace(")", "") + ".bpmn")
            path.write_text(text)
            row = {"workload": name, "bpmnBytes": len(text.encode()), "bpmnNodes": bpmn_nodes(text)}
            if mods:
                row["prototype"] = bench_legacy(mods, path, repeats)
            row["glovebox"] = bench_glovebox(text.encode(), profile, stress_profile, repeats)
            rows.append(row)
            proto = row.get("prototype", {})
            gb = row["glovebox"]
            print(f"{name:28s} nodes={row['bpmnNodes']:5d} xml={row['bpmnBytes']:7d}B | "
                  f"prototype {proto.get('totalMs', float('nan')):7.2f} ms {proto.get('outputBytes', 0):7d}B "
                  f"states={proto.get('states', 0):5d} | glovebox "
                  + (f"rejected ({gb['diagnostics']} diagnostics)" if gb["rejected"] else
                     f"{gb['compileMs']:6.2f} ms {gb['payloadBytes']:7d}B states={gb['states']:5d} "
                     f"validate={gb['validateMsPython']:.1f} ms"))
        # Revocation fidelity: k REVOKE_CREDENTIAL tasks on the sequence flow or in an event subprocess.
        fidelity_rows = []
        fidelity_profile = WalletProfile(fidelity_profile_data(data))
        for placement in ("flow", "event-subprocess"):
            for k in range(0, 7):
                text = fidelity(k, placement)
                path = Path(tmp) / f"fidelity_{placement}_{k}.bpmn"
                path.write_text(text)
                row = {"placement": placement, "authored": k}
                if mods:
                    row["prototypeEmitted"] = bench_legacy(mods, path, 5)["revocationStates"]
                try:
                    package, _ = compile_bpmn(text.encode(), fidelity_profile)
                    row["gloveboxEmitted"] = sum(1 for st in package["states"].values()
                                                 if st.get("action", {}).get("type") == "REVOKE_CREDENTIAL")
                    row["gloveboxRejected"] = False
                except CompileError as exc:
                    row["gloveboxEmitted"] = None
                    row["gloveboxRejected"] = True
                    row["gloveboxDiagnostics"] = [getattr(d, "message", str(d)) for d in exc.diagnostics]
                fidelity_rows.append(row)
                print(f"fidelity {placement:17s} k={k} prototype={row.get('prototypeEmitted')} "
                      f"glovebox={'rejected' if row['gloveboxRejected'] else row['gloveboxEmitted']}")
        cli = {}
        if mods:
            for name in ("hospitality export", "linear 1000 (mixed)"):
                text = next(t for n, t, _ in workloads if n == name)
                path = Path(tmp) / "cli.bpmn"
                path.write_text(text)
                cli[name] = cli_ms(path)
            start = median_ms(lambda: subprocess.run([sys.executable, "-c", "import networkx"],
                                                     capture_output=True, check=True), 10)
            cli["interpreter start and networkx import"] = start
            print("CLI end-to-end (ms):", {k: round(v, 1) for k, v in cli.items()})
    # Large packages for the Swift validator, with the state bound lifted (stress profile).
    stress_vectors = [{"id": r["workload"], "expected": "ACCEPTED", "jws": r["glovebox"]["jws"]}
                      for r in rows if not r["glovebox"]["rejected"]]
    (ROOT / "vectors" / "stress_vectors.json").write_text(json.dumps(stress_vectors) + "\n")
    (ROOT / "profile" / "stress_profile.json").write_text(json.dumps(stress, indent=2, sort_keys=True) + "\n")
    for r in rows:
        r["glovebox"].pop("jws", None)
    out = {"workloads": rows, "cliMs": cli, "fidelity": fidelity_rows, "python": sys.version.split()[0]}
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "compilation.json").write_text(json.dumps(out, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
