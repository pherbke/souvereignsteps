import re
import networkx as nx
from collections import deque


##### Potential TODO's #####
# TODO: fix guard gateway detection                 replace hardcoded BRANCHING_GATEWAYS list with real detection logic, maybe ask Dennis to change BPMN for deterministic detection                    
# TODO: validation layer                            only partially there

# ----------------------------------------------------------
# CONFIGURATION FIELDS - may be adjusted for other use cases
# ----------------------------------------------------------
NON_PARAM_FIELDS = {"description", "type", "actionType", "gatewayType", "eventType", "messageRef", "duration", "signalRef"}
# ARRAY-FIELDS are fields, where it is legal to perform a split(",") operation on comma seperated strings
ARRAY_FIELDS = {"presentationRequest", "permissions"}
# EVENT-EMITTING-ACTION-TYPES always branch for successfull (task.success) or failed execution (task.failure)
EVENT_EMITTING_ACTION_TYPES = {"VERIFY_LOCAL_CREDENTIAL", "PRESENT_CREDENTIAL", "REQUEST_VC", "PROCESS_PAYMENT", "REVOKE_CREDENTIAL"}
FIRE_AND_FORGET_ACTION_TYPES = {"USER_NOTIFICATION", "ACTIVATE_REMOTE_CONTROL", "USER_CONSENT", "REQUEST_USER_INPUT"}
# hardcoded dict of guard gateways
GUARD_GATEWAYS = {"EG_Dynamic"}
# SUCCESS regex pattern to determine edge label meaning
SUCCESS_RE = re.compile(
    r"\b(ja|yes|true|ok|success|successful|erfolgreich|done|completed|valid)\b",
    re.IGNORECASE
)
# FAILURE regex pattern to determine edge label meaning
FAILURE_RE = re.compile(
    r"\b(nein|no|false|fail|failure|error|abbruch|cancel|invalid|fehlgeschlagen)\b",
    re.IGNORECASE
)
# map BPMN action types to function names from wallet
ACTION_TYPE_DICT = {
    "VERIFY_LOCAL_CREDENTIAL": "verifyLocalCredential", 
    "PRESENT_CREDENTIAL": "presentVC", 
    "REQUEST_VC": "requestVC", 
    "PROCESS_PAYMENT": "processPayment", 
    "REVOKE_CREDENTIAL": "revokeCredential",
    "USER_NOTIFICATION": "notifyUser",
    "ACTIVATE_REMOTE_CONTROL": "activateRemoteControl",
    "USER_CONSENT": "requestUserConsent",
    "REQUEST_USER_INPUT": "requestUserInput"
}

# ---------------------------------
# HELPER FUNCTIONS 
# ---------------------------------
# normalize guard label
def normalize_guard_label(label: str):
    label = re.sub(r"[^a-zA-Z0-9\s]", "", label)
    return "".join(word[:1].upper() + word[1:] for word in label.split())

# maps an edge label to either "success", "failure" or None
def normalize_edge_label(label: str):
    if not label:
        return None

    label = label.strip().lower()

    if SUCCESS_RE.search(label):
        return "success"
    

    if FAILURE_RE.search(label):
        return "failure"

    return None

# converts ISO 8601 time strings into milliseconds integer
def convert_time_to_milliseconds(time: str):
    if not time:
        return None
    
    match = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?", time)

    if not match:
        raise ValueError(f"Invalid duration format: {time}")
    
    hours = int(match.group(1) or 0)
    minutes = int(match.group(2) or 0)
    seconds = int(match.group(3) or 0)

    return (hours * 3600 + minutes * 60 + seconds) * 1000

# type matches given value strings to Boolean, Integer, Float
def normalize_value(v):
    if isinstance(v, str):
        # boolean
        if v.lower() == "true":
            return True
        if v.lower() == "false":
            return False

        # int
        if v.isdigit():
            return int(v)

        # float
        try:
            if "." in v:
                return float(v)
        except:
            pass

    return v

# applies normalization for all values in context
def normalize_context(context: dict):
    return {
        k: normalize_value(v)
        for k, v in context.items()
    }

# handles branching gateways in intermediate graph representation:
# - outgoing edges of gateway get assigned to predecessor node
# - delete gateway from intermediate graph
def collapse_branching_gateways(graph: nx.DiGraph):
    branching_gateways = [
        n for n, data in graph.nodes(data=True)
        if data.get("gatewayType") == "branching" 
            and n not in GUARD_GATEWAYS
    ]

    for gw in branching_gateways:
        incoming = list(graph.in_edges(gw, data=True))
        outgoing = list(graph.out_edges(gw, data=True))

        # if outgoing[0]["type"]=="intermediateCatchEvent":
        #     continue

        # safety check
        if len(incoming) != 1:
            raise ValueError(f"Gateway {gw} must have exactly 1 incoming edge")

        pred, _, _ = incoming[0]

        # rewire: predecessor → all successors
        for _, succ, edge_data in outgoing:
            graph.add_edge(pred, succ, **edge_data)

        # remove gateway
        graph.remove_node(gw)

# BFS traversal to determine order of states in final xstate (order doesnt matter for execution but better readability)
def traversal_order(graph, start):
    visited = set()
    queue = deque([start])
    order = []

    while queue:
        node = queue.popleft()

        if node in visited:
            continue

        visited.add(node)
        order.append(node)

        for succ in graph.successors(node):
            if succ not in visited:
                queue.append(succ)

    return order

# adds action related fields to state
def add_action(node, state: dict, node_data: dict, xstate):
    action_type = node_data.get("actionType")

    # no action attached to node or pseudo action TRIGGER_WORKFLOW 
    if not action_type or action_type=="TRIGGER_WORKFLOW":
        return
    
    params = {}

    # collect params from node_data
    for key, _ in node_data.items():
        if key in NON_PARAM_FIELDS:
            continue
        
        # applicable if multiple nodes have the same params
        if node + key in xstate["context"]:
            params[key] = f"context.{node + key}"
        else:    
            params[key] = f"context.{key}"

    state["entry"] = {
        "type": ACTION_TYPE_DICT.get(action_type),
        "params": params
    }

# adds transitions for a single node
def add_transitions_for_single_node(state: dict, graph: nx.DiGraph, node: str, node_data):
    out_edges = list(graph.out_edges(node, data=True))

    # CASE 0: no outgoing edges (End State) 
    if not out_edges:
        return
    
    action_type = node_data.get("actionType")
    is_event_emitting = action_type in EVENT_EMITTING_ACTION_TYPES
    is_guard_gateway = node in GUARD_GATEWAYS

    # CASE 1: event emitting node -> event-based "success" / "failure" transitions
    if is_event_emitting:

        # CASE 1.1: one outgoing edge -> assume the outgoing edge is the "success" path, failure will be redirected to artificial "FAIL_STATE"
        if len(out_edges) == 1:
            _, target, _ = out_edges[0]
            state["on"] = {
                f"{ACTION_TYPE_DICT[action_type]}.success": {"target": target},
                f"{ACTION_TYPE_DICT[action_type]}.failure": {"target": "FAIL_STATE"}
            }

        # CASE 1.2: 2 outgoing edges -> check edge labels to determine "sucess" / "failure" paths
        elif len(out_edges) == 2:
            (_, target1, data1), (_, target2, data2) = out_edges
            normalized_label1 = normalize_edge_label(data1.get("name"))
            normalized_label2 = normalize_edge_label(data2.get("name"))

            if normalized_label1 == "success" and normalized_label2 == "failure":
                state["on"] = {
                    f"{ACTION_TYPE_DICT[action_type]}.success": {"target": target1},
                    f"{ACTION_TYPE_DICT[action_type]}.failure": {"target": target2}
                }
                return
            elif normalized_label1 == "failure" and normalized_label2 == "success":
                state["on"] = {
                    f"{ACTION_TYPE_DICT[action_type]}.success": {"target": target2},
                    f"{ACTION_TYPE_DICT[action_type]}.failure": {"target": target1}
                }
                return

            # fallback: first edge becomes "success" path, second edge becomes "failure" path
            state["on"] = {
                f"{ACTION_TYPE_DICT[action_type]}.success": {"target": target1},
                f"{ACTION_TYPE_DICT[action_type]}.failure": {"target": target2}
            }
        return  
    
    # CASE 2: guard gateway -> eventless transition with guard
    elif is_guard_gateway and len(out_edges) == 2:
        guard = normalize_guard_label(node_data["description"])
        (_, target1, data1), (_, target2, data2) = out_edges
        normalized_label1 = normalize_edge_label(data1.get("name"))
        normalized_label2 = normalize_edge_label(data2.get("name"))

        if normalized_label1 == "success" and normalized_label2 == "failure":
            state["always"] = [
                {
                    "guard": f"context.{guard}",
                    "target": target1
                },
                {
                    "target": target2 
                }
            ]
        else:
            state["always"] = [
                {
                    "guard": f"context.{guard}",
                    "target": target2
                },
                {
                    "target": target1
                }
            ]
        return      
                
    # CASE 3: not event-emitting / guard-gateway 
    else:
        # CASE 3.1: not event-emitting / guard-gateway with 1 outhgoing edge -> eventless transition without guard
        if len(out_edges) == 1:
            _, target, _ = out_edges[0]
            state["always"] = {"target": target}
            return
        # CASE 3.2: not event-emitting / guard-gateway with 2 (or more) outgoing edges -> could be a "dead-end" or event-based gateway
        else: 
            _, target, _ = out_edges[0]
            next_node_is_event = graph.nodes[target].get("eventType") is not None
            print(next_node_is_event)

            # CASE 3.2.1: "dead-end" -> keep branch with "sucess" label and ignore other
            if not next_node_is_event:
                (_, target1, data1), (_, target2, data2) = out_edges
                normalized_label1 = normalize_edge_label(data1.get("name"))
                normalized_label2 = normalize_edge_label(data2.get("name"))

                if normalized_label1 == "success":
                    state["always"] = {"target": target1}
                else:
                    state["always"] = {"target": target2}

                return    

            # CASE 3.2.2: Event based Gateway -> event-based "on EVENT" / "after TIME" transitions
            else:
                event_transitions = {}

                for _, target, _ in out_edges:
                    target_data = graph.nodes[target]

                    event_type = target_data.get("eventType")

                    successor_edges = list(graph.out_edges(target, data=True))
                    successor = successor_edges[0][1] if successor_edges else None

                    if not event_type:
                        continue

                    if event_type == "message":
                        event_key = target_data.get("messageRef", "MESSAGE")

                    elif event_type == "signal":
                        event_key = target_data.get("signalRef", "SIGNAL")

                    elif event_type == "timer":
                        duration = target_data.get("duration", "0")
                        duration_milliseconds = convert_time_to_milliseconds(duration)

                        state.setdefault("after", {})
                        state["after"][duration_milliseconds] = {"target": successor}
                        continue
                    
                    # fallback for unknown Event Type
                    else:
                        event_key = event_type.upper()

                    event_transitions[event_key] = {"target": successor}

                if event_transitions:
                    state["on"] = event_transitions

                return

# adds the generic "FAIL_STATE" if:
# - its not already there (not has_fail_state)
# - was referenced by other states (fail_referenced)
def ensure_fail_state(xstate: dict):
    has_fail_state = "FAIL_STATE" in xstate["states"]

    if has_fail_state:
        return

    fail_referenced = any(
        ("FAIL_STATE" == (t.get("target") if isinstance(t, dict) else None))
        for state in xstate["states"].values()
        for t in (
            [state.get("always")]
            if state.get("always")
            else list(state.get("on", {}).values())
        )
    )

    if fail_referenced:
        xstate["states"]["FAIL_STATE"] = {
            "description": "Process failed.",
            "type": "final"
        }

# deletes all non-starting nodes that don't have predecessors
def delete_unreachable_states(xstate):
    reachable = set()
    stack = [xstate["initial"]]

    while stack:
        state = stack.pop()

        if state in reachable:
            continue

        reachable.add(state)

        state_def = xstate["states"].get(state, {})

        # always transitions
        always = state_def.get("always")
        if isinstance(always, dict):
            stack.append(always["target"])
        elif isinstance(always, list):
            for t in always:
                stack.append(t["target"])

        # on transitions
        for t in state_def.get("on", {}).values():
            stack.append(t["target"])

    xstate["states"] = {
        k: v
        for k, v in xstate["states"].items()
        if k in reachable
    }      

# -------------------------------------------------
# MAIN API FUNCTION: COMPILE XSTATE FROM BPMN GRAPH
# in: intermediate BPNM graph representation
# out: XState object
# -------------------------------------------------
def compile_xstate(bpmn: nx.DiGraph, process_id: str):
    # -------------------------------------------------
    # PREPARATION: COLLAPSE BRANCHING GATEWAYS IN GRAPH
    # -------------------------------------------------
    collapse_branching_gateways(bpmn)
    # ---------------------------------
    # 1) DEFINING XSTATE BASE STRUCTURE
    # ---------------------------------
    initial_state = next(n for n in bpmn.nodes if bpmn.in_degree(n) == 0)
    xstate = {
        "id": process_id,
        "initial": initial_state,
        "context": {},
        "states": {}
    }
    # ----------------------------------
    # 2) FILLING CONTEXT FIELD OF XSTATE
    # ----------------------------------
    for node, data in bpmn.nodes(data=True):
        # guard handling: default to true
        if node in GUARD_GATEWAYS:
            guard = normalize_guard_label(data.get("description"))
            xstate["context"][guard] = True

        for key, value in data.items():
            if key in NON_PARAM_FIELDS:
                continue
            
            # split "array"-strings into Arrays
            if key in ARRAY_FIELDS and isinstance(value, str):
                if "," in value:
                    value = [v.strip() for v in value.split(",")]
                else:
                    value = [value.strip()]

            # checks if context already contains the parameter -> if yes, key has to become unique to avoid overwrite of params
            if key not in xstate["context"]:
                xstate["context"][key] = normalize_value(value)
            else: 
                xstate["context"][node + key] = normalize_value(value)  

            
    # -------------------------------------------------------------------
    # 3) CREATING STATES AND ADDING DESCRIPTION, ACTIONS, AND TRANSITIONS
    # -------------------------------------------------------------------
    for node in traversal_order(bpmn, initial_state):
        node_data = bpmn.nodes[node]

        state = {
            "description": node_data.get("description", "")
        }

        # adding "final" tag to states that represent endEvents
        if node_data["type"] == "endEvent":
            state["type"] = "final"
            xstate["states"][node] = state
            continue

        add_action(node, state, node_data, xstate)

        add_transitions_for_single_node(state, bpmn,node, node_data)

        xstate["states"][node] = state

    # ---------------------------
    # 4) ADD FAIL_STATE IF NEEDED
    # ---------------------------
    ensure_fail_state(xstate)

    # -----------------------------------------------------------
    # 5) DELETING NODES THAT ARE NOT REACHABLE FROM INITIAL STATE
    # -----------------------------------------------------------
    delete_unreachable_states(xstate)

 
    return xstate
