import networkx as nx
import xml.etree.ElementTree as ET

# Namespace Definitions for XML Elements
ns = {
    "bpmn": "http://www.omg.org/spec/BPMN/20100524/MODEL",
    "camunda": "http://camunda.org/schema/1.0/bpmn"
}

# legal Nodes: basic BPMN elements (events, tasks, gateways)
node_tags = [
    "task",
    "startEvent",
    "endEvent",
    "intermediateCatchEvent",
    "exclusiveGateway",
    "eventBasedGateway"
]

def _annotate_gateways(G: nx.DiGraph):
    for node in G.nodes:
        node_type = G.nodes[node].get("type")

        if "Gateway" not in node_type:
            continue

        in_deg = G.in_degree(node)
        out_deg = G.out_degree(node)

        if in_deg <= 1 and out_deg > 1:
            G.nodes[node]["gatewayType"] = "branching"

        elif in_deg > 1 and out_deg <= 1:
            G.nodes[node]["gatewayType"] = "merging"

        elif in_deg > 1 and out_deg > 1:
            G.nodes[node]["gatewayType"] = "mixed"

        else:
            G.nodes[node]["gatewayType"] = "unknown"

def _extract_intermediate_event_data(elem):
    data = {}

    # message
    msg = elem.find("bpmn:messageEventDefinition", ns)
    if msg is not None:
        data["eventType"] = "message"
        data["messageRef"] = msg.get("messageRef")

    # signal
    sig = elem.find("bpmn:signalEventDefinition", ns)
    if sig is not None:
        data["eventType"] = "signal"
        data["signalRef"] = sig.get("signalRef")

    # timer
    timer = elem.find("bpmn:timerEventDefinition", ns)
    if timer is not None:
        data["eventType"] = "timer"
        time_duration = timer.find("bpmn:timeDuration", ns)
        if time_duration is not None:
            data["duration"] = time_duration.text

    # conditional
    cond = elem.find("bpmn:conditionalEventDefinition", ns)
    if cond is not None:
        data["eventType"] = "conditional"

    # link (optional)
    link = elem.find("bpmn:linkEventDefinition", ns)
    if link is not None:
        data["eventType"] = "link"

    return data

# -----------------------------
# 1. build the full BPMN graph
# -----------------------------
def _build_graph(bpmn: ET.Element) -> nx.DiGraph:
    G = nx.DiGraph()

    for tag in node_tags:
        for elem in bpmn.findall(f".//bpmn:{tag}", ns):

            node_id = elem.get("id")
            if not node_id:
                continue

            data = {
                "type": tag,
                "description": elem.get("name", "")
            }

            for prop in elem.findall(".//camunda:property", ns):
                data[prop.get("name")] = prop.get("value")

            if tag == "intermediateCatchEvent":
                data.update(_extract_intermediate_event_data(elem))

            G.add_node(node_id, **data)

    for flow in bpmn.findall(".//bpmn:sequenceFlow", ns):

        source = flow.get("sourceRef")
        target = flow.get("targetRef")

        if source and target:
            G.add_edge(
                source,
                target,
                id=flow.get("id"),
                name=flow.get("name", "")
            )

    return G


# -----------------------------
# 2. find the root of the Graph (marked with "actionType" == "TRIGGER_WORKFLOW") - Start for the Workflow
# -----------------------------
def _find_root(G: nx.DiGraph):
    for node, data in G.nodes(data=True):
        if data.get("actionType") == "TRIGGER_WORKFLOW":
            return node
    return None


# -----------------------------
# 3. delete the unneccessary nodes and edges (before root)
# -----------------------------
def _filter_from_root(G: nx.DiGraph) -> nx.DiGraph:
    root = _find_root(G)

    if root is None:
        return G  # fallback: no filtering

    reachable = nx.descendants(G, root)
    reachable.add(root)

    return G.subgraph(reachable).copy()


# -----------------------------
# public API 
# -----------------------------
def build_bpmn_graph(bpmn: ET.Element) -> nx.DiGraph:
    G = _build_graph(bpmn)
    _annotate_gateways(G)
    return _filter_from_root(G)