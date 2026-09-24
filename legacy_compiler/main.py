import json
import os
import shutil
import sys

from parser import parse_xml
from graph import build_bpmn_graph
from compiler import compile_xstate

def run_debug(graph):
    print("DEBUG mode: data from intermediate graph representation")
    print("\nNODES:")
    for node, data in graph.nodes(data=True):
        print(node)

    print("\nEDGES:")
    for origin, destination, data in graph.edges(data=True):
        print(origin, "->", destination, data)

    print("\nCONTEXT:")
    for node, data in graph.nodes(data=True):
        for key, value in data.items():
            if key not in {"name", "type", "actionType"}:
                print(f"{node} - {key}: {value}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 main.py <input_xml_file> <output_json_file> [--debug / --demo]")
        sys.exit(1)

    bpmn_file = sys.argv[1]
    output_file = sys.argv[2]
    debug = "--debug" in sys.argv
    demo = "--demo" in sys.argv

    # for the demo, the compiler just copies an already defined json into the user specified directory
    static_file_path = os.path.join(os.path.dirname(__file__), "examples/uc1-dynamic-hospitality.json")

    # for the demo, the compiler just copies an already defined json into the user specified directory
    static_file_path = os.path.join(os.path.dirname(__file__), "examples/uc1-dynamic-hospitality.json")

    try:
        bpmn_xml = parse_xml(bpmn_file)

        ns = {"bpmn": "http://www.omg.org/spec/BPMN/20100524/MODEL"}
        process = bpmn_xml.find(".//bpmn:process", ns)

        if process is None:
            raise ValueError("No BPMN process found")

        process_id = process.attrib.get("id", "unknown")

        graph = build_bpmn_graph(bpmn_xml)
        xstate = compile_xstate(graph, process_id)

        if demo:
            shutil.copyfile(static_file_path, output_file)
            print(f"[DEMO] JSON file written to {output_file}")
        else:
            with open(output_file, "w") as f:
                json.dump(xstate, f, indent=2)

            print(f"JSON file written to {output_file}")    

        if debug:
            run_debug(graph)

    except FileNotFoundError:
        print(f"Error: File not found -> {bpmn_file}")
        sys.exit(1)

if __name__ == "__main__":
    main()