"""Restricted BPMN 2.0 compiler.

The compiler reads the models exported by the prototype's low-code editor:
standard BPMN 2.0 XML whose tasks carry ``camunda:property`` entries, with
``actionType`` naming the wallet action. It accepts a deliberately small
subset: one none start event, typed tasks, exclusive gateways that branch on
the preceding task's outcome, and end events with a declared result.
Everything else fails compilation with a diagnostic that names the offending
element. Nothing is pruned or dropped silently.

Pass 1 (structure)   supported elements, one start, well-formed flows
Pass 2 (typing)      bind tasks to action schemas, type parameters, outcomes
Pass 3 (capability)  action types exist in the target wallet profile;
                     network actions map 'offline' explicitly
Pass 4 (packaging)   identifier, version, expiry, state table;
                     unreachable nodes and cycles are errors
"""

import re
import xml.etree.ElementTree as ET

from . import SCHEMA
from .validator import DECIMAL_RE, find_back_edges, origin

CAMUNDA_NS = "http://camunda.org/schema/1.0/bpmn"
TASK_TAGS = {"task", "userTask", "serviceTask", "sendTask", "receiveTask", "manualTask"}
NODE_TAGS = TASK_TAGS | {"startEvent", "endEvent", "exclusiveGateway"}
# Non-executable annotations that cannot influence control flow.
IGNORED_TAGS = {
    "documentation", "extensionElements", "laneSet", "textAnnotation",
    "association", "group", "dataObject", "dataObjectReference",
    "dataStoreReference",
}
TASK_CHILDREN = {"documentation", "extensionElements", "incoming", "outgoing"}
EVENT_CHILDREN = {"documentation", "extensionElements", "incoming", "outgoing"}
OUTCOME_RE = re.compile(r"""^\$\{\s*outcome\s*==\s*(['"])([A-Za-z][A-Za-z0-9]*)\1\s*\}$""")
TERMINAL_KINDS = ("success", "deny", "error")


class Diagnostic:
    def __init__(self, code, element, message):
        self.code = code
        self.element = element
        self.message = message

    def as_dict(self):
        return {"code": self.code, "element": self.element, "message": self.message}

    def __repr__(self):
        return f"{self.code}[{self.element}]: {self.message}"


class CompileError(Exception):
    def __init__(self, diagnostics):
        super().__init__("; ".join(repr(d) for d in diagnostics))
        self.diagnostics = diagnostics

    @property
    def codes(self):
        return sorted({d.code for d in self.diagnostics})


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _child(elem, name):
    for sub in elem:
        if _local(sub.tag) == name:
            return sub
    return None


def _properties(elem, diags):
    props = {}
    ext = _child(elem, "extensionElements")
    if ext is None:
        return props
    for prop in ext.iter(f"{{{CAMUNDA_NS}}}property"):
        name = prop.get("name")
        if name in props:
            diags.append(Diagnostic("E_STRUCTURE", elem.get("id"), f"property {name} repeats"))
        props[name] = prop.get("value", "")
    return props


class _Flow:
    def __init__(self, elem):
        self.id = elem.get("id")
        self.source = elem.get("sourceRef")
        self.target = elem.get("targetRef")
        cond = _child(elem, "conditionExpression")
        self.condition = None if cond is None else (cond.text or "").strip()


def _typed(nid, atype, name, raw, rule, diags):
    """Convert an editor string property into a typed package parameter."""
    kind = rule["type"]
    if kind == "list":
        return [item.strip() for item in raw.split(",") if item.strip()]
    if kind == "enum" and raw not in rule["values"]:
        diags.append(Diagnostic("E_PARAM", nid, f"{name}={raw!r} is not permitted for {atype}"))
    if kind == "decimal" and not DECIMAL_RE.match(raw):
        diags.append(Diagnostic("E_PARAM", nid, f"{name}={raw!r} is not a decimal amount"))
    if kind == "endpoint" and origin(raw) is None:
        diags.append(Diagnostic("E_ENDPOINT", nid, f"{name}={raw!r} is not an https URL"))
    if raw.startswith("context."):
        diags.append(Diagnostic("E_PARAM", nid,
                                f"{name} refers to {raw}; packages carry literals, not expressions"))
    return raw


def compile_bpmn(source, profile):
    """Compile BPMN XML (bytes or str) into an unsigned package and a report."""
    diags = []
    root = ET.fromstring(source)
    for child in root:
        if _local(child.tag) in {"collaboration", "choreography"}:
            diags.append(Diagnostic("E_UNSUPPORTED", child.get("id"),
                                    f"{_local(child.tag)} is outside the supported subset"))
    processes = [c for c in root if _local(c.tag) == "process"]
    if len(processes) != 1:
        diags.append(Diagnostic("E_STRUCTURE", root.get("id"), "exactly one process is required"))
        raise CompileError(diags)
    process = processes[0]

    # ---- Pass 1: structure ---------------------------------------------------
    nodes, flows, unsupported = {}, {}, set()
    for child in process:
        tag = _local(child.tag)
        cid = child.get("id")
        if tag in NODE_TAGS:
            nodes[cid] = (tag, child)
        elif tag == "sequenceFlow":
            flows[cid] = _Flow(child)
        elif tag in IGNORED_TAGS:
            continue
        else:
            detail = tag
            if tag == "subProcess" and child.get("triggeredByEvent") == "true":
                detail = "event subprocess"
            diags.append(Diagnostic("E_UNSUPPORTED", cid, f"{detail} is outside the supported subset"))
            unsupported.add(cid)

    for nid, (tag, elem) in nodes.items():
        allowed = TASK_CHILDREN if tag in TASK_TAGS else EVENT_CHILDREN
        for sub in elem:
            name = _local(sub.tag)
            if tag == "exclusiveGateway" and name in {"incoming", "outgoing", "documentation", "extensionElements"}:
                continue
            if tag != "exclusiveGateway" and name not in allowed:
                diags.append(Diagnostic("E_UNSUPPORTED", nid,
                                        f"{name} on {tag} is outside the supported subset"))
        if tag in TASK_TAGS and elem.get("isForCompensation") == "true":
            diags.append(Diagnostic("E_UNSUPPORTED", nid, "compensation tasks are unsupported"))

    starts = [nid for nid, (tag, _) in nodes.items() if tag == "startEvent"]
    if len(starts) != 1:
        diags.append(Diagnostic("E_START", process.get("id"), f"{len(starts)} start events; exactly one required"))

    outgoing = {nid: [] for nid in nodes}
    incoming = {nid: [] for nid in nodes}
    for flow in flows.values():
        if flow.source in unsupported or flow.target in unsupported:
            continue
        if flow.source not in nodes or flow.target not in nodes:
            diags.append(Diagnostic("E_STRUCTURE", flow.id, "flow references an unknown node"))
            continue
        outgoing[flow.source].append(flow)
        incoming[flow.target].append(flow)
    if diags:
        raise CompileError(diags)

    for nid, (tag, elem) in nodes.items():
        outs, ins = outgoing[nid], incoming[nid]
        if tag == "startEvent" and len(outs) != 1:
            diags.append(Diagnostic("E_STRUCTURE", nid, "the start event needs one outgoing flow"))
        if tag == "endEvent" and outs:
            diags.append(Diagnostic("E_STRUCTURE", nid, "end events cannot have outgoing flows"))
        if tag in TASK_TAGS and len(outs) != 1:
            diags.append(Diagnostic("E_STRUCTURE", nid, "tasks need exactly one outgoing flow; branch with a gateway"))
        if tag != "exclusiveGateway":
            for flow in outs:
                if flow.condition is not None:
                    diags.append(Diagnostic("E_CONDITION", flow.id,
                                            "conditions are only supported on exclusive-gateway branches"))
        if tag == "exclusiveGateway":
            if len(outs) > 1 and len(ins) > 1:
                diags.append(Diagnostic("E_STRUCTURE", nid, "mixed gateways are unsupported"))
            if not outs:
                diags.append(Diagnostic("E_STRUCTURE", nid, "gateway without outgoing flow"))
            if len(outs) > 1:
                if len(ins) != 1 or nodes[ins[0].source][0] not in TASK_TAGS:
                    diags.append(Diagnostic("E_STRUCTURE", nid,
                                            "a diverging gateway must directly follow one task"))
                default = elem.get("default")
                for flow in outs:
                    if flow.id == default:
                        continue
                    if flow.condition is None or not OUTCOME_RE.match(flow.condition):
                        diags.append(Diagnostic("E_CONDITION", flow.id,
                                                f"condition {flow.condition!r} is not an outcome test"))
    if diags:
        raise CompileError(diags)

    def resolve(target):
        """Follow merging gateways to the next task or end event."""
        seen = set()
        while nodes[target][0] == "exclusiveGateway" and len(outgoing[target]) == 1:
            if target in seen:
                raise CompileError([Diagnostic("E_CYCLE", target, "cycle through merging gateways")])
            seen.add(target)
            target = outgoing[target][0].target
        return target

    # ---- Pass 2: typing ------------------------------------------------------
    states, defaults_used = {}, {}
    for nid in [n for n, (tag, _) in nodes.items() if tag in TASK_TAGS]:
        props = _properties(nodes[nid][1], diags)
        atype = props.pop("actionType", None)
        if not atype:
            diags.append(Diagnostic("E_UNBOUND_TASK", nid, "task is not bound to a wallet action"))
            continue
        if atype not in profile.handlers:
            states[nid] = {"action": {"type": atype, "params": props}, "on": {}}
            continue  # reported by the capability pass
        spec = profile.handlers[atype]
        params = {}
        for name, raw in props.items():
            rule = spec["params"].get(name)
            if rule is None:
                diags.append(Diagnostic("E_PARAM", nid, f"unknown parameter {name} for {atype}"))
                continue
            params[name] = _typed(nid, atype, name, raw, rule, diags)
        for name, rule in spec["params"].items():
            required = rule.get("required", False)
            if "requiredIf" in rule:
                required = all(params.get(k) == v for k, v in rule["requiredIf"].items())
            if required and name not in params:
                diags.append(Diagnostic("E_PARAM", nid, f"missing parameter {name} for {atype}"))

        outcomes = spec["outcomes"]
        on = {}
        (flow,) = outgoing[nid]
        target = resolve(flow.target)
        if nodes[target][0] == "exclusiveGateway":
            default = nodes[target][1].get("default")
            default_target = None
            for branch in outgoing[target]:
                if branch.id == default:
                    default_target = resolve(branch.target)
                    continue
                outcome = OUTCOME_RE.match(branch.condition).group(2)
                if outcome not in outcomes:
                    diags.append(Diagnostic("E_OUTCOME", branch.id, f"{atype} never returns {outcome!r}"))
                    continue
                if outcome in on:
                    diags.append(Diagnostic("E_OUTCOME", branch.id, f"outcome {outcome!r} branches twice"))
                on[outcome] = resolve(branch.target)
            if default_target is not None:
                covered = [o for o in outcomes if o not in on]
                defaults_used[nid] = covered
                for outcome in covered:
                    on[outcome] = default_target
        else:
            on[outcomes[0]] = target
        states[nid] = {"action": {"type": atype, "params": params}, "on": on}

    # ---- Pass 3: capability and offline outcomes -------------------------------
    for nid, state in states.items():
        action = state["action"]
        if action["type"] not in profile.handlers:
            diags.append(Diagnostic("E_CAPABILITY", nid,
                                    f"target wallet profile has no handler for {action['type']!r}"))
            continue
        try:
            locality = profile.locality(action)
        except KeyError:
            diags.append(Diagnostic("E_PARAM", nid, "parameter selecting the locality is invalid"))
            continue
        if locality == "network" and "offline" not in state["on"]:
            diags.append(Diagnostic("E_OFFLINE_UNMAPPED", nid,
                                    "network action must map the 'offline' outcome explicitly"))

    if diags:
        raise CompileError(diags)

    # ---- Pass 4: packaging -----------------------------------------------------
    for nid, (tag, elem) in nodes.items():
        if tag == "endEvent":
            result = _properties(elem, diags).get("result")
            if result not in TERMINAL_KINDS:
                diags.append(Diagnostic("E_TERMINAL", nid, "end event needs result success|deny|error"))
            states[nid] = {"terminal": result}
    initial = resolve(outgoing[starts[0]][0].target) if starts else None
    if initial is not None and nodes[initial][0] not in TASK_TAGS:
        diags.append(Diagnostic("E_STRUCTURE", initial, "the start event must lead to a task"))

    reached, frontier = set(), [initial] if initial else []
    while frontier:
        sid = frontier.pop()
        if sid in reached:
            continue
        reached.add(sid)
        frontier.extend(states.get(sid, {}).get("on", {}).values())
    for nid in sorted(set(states) - reached):
        diags.append(Diagnostic("E_UNREACHABLE", nid, "node is unreachable from the start event"))

    if initial:
        for source, target in find_back_edges(initial, lambda sid: states.get(sid, {}).get("on", {}).values()):
            diags.append(Diagnostic("E_CYCLE", source, f"cycle through {source} -> {target}"))

    proc_props = _properties(process, diags)
    for key in ("packageId", "version", "minVersion", "notAfter"):
        if key not in proc_props:
            diags.append(Diagnostic("E_PACKAGE", process.get("id"), f"missing process property {key}"))
    if diags:
        raise CompileError(diags)

    package = {
        "schema": SCHEMA,
        "id": proc_props["packageId"],
        "version": int(proc_props["version"]),
        "floor": int(proc_props["minVersion"]),
        "notAfter": proc_props["notAfter"],
        "initial": initial,
        "states": {sid: states[sid] for sid in sorted(states)},
    }
    report = {
        "bpmnNodes": len(nodes),
        "bpmnFlows": len(flows),
        "states": len(states),
        "transitions": sum(len(s.get("on", {})) for s in states.values()),
        "defaultCovered": defaults_used,
        "failClosedOutcomes": {
            sid: [o for o in profile.outcomes(s["action"]["type"]) if o not in s["on"]]
            for sid, s in states.items() if "action" in s
        },
    }
    return package, report
