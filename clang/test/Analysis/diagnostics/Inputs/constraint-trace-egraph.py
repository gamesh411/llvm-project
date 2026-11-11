#!/usr/bin/env python3
"""Print, for each Path Step of each diagnostic's constraint trace, the
analyzer node its snapshot came from, so a test can FileCheck it.

A step prints as `<label>: N<index> <kind> @<line>:<col> in <stack>`, where
index points into `exploded_nodes`, and the stack reads innermost first as
`callee <- caller@<line>:<col>`, the location being the call site in the
caller. A step without a node prints NO-NODE. Before the steps, every node is
checked against the table invariants, which print BAD-TABLE when broken, and
the trace prints how many of its nodes share an ID with an earlier one.
"""

import plistlib
import sys

import constraint_trace


def render_location(files, location):
    if location is None:
        return "@none"
    return "@%s:%d:%d" % (files[location["file"]].rsplit("/", 1)[-1],
                          location["line"], location["col"])


def render_stack(files, frames, index):
    parts = []
    while index is not None:
        frame = frames[index]
        part = frame["function"]
        if "call_site" in frame:
            part += " called " + render_location(files, frame["call_site"])
        parts.append(part)
        index = frame.get("parent")
    return " <- ".join(parts)


def step_label(piece):
    if piece["kind"] == "control":
        end = piece["edges"][0]["end"][0]
        return "CONTROL ending at %d:%d" % (end["line"], end["col"])
    return 'EVENT "%s"' % piece["message"]


def check_tables(nodes, frames):
    positions = [node["path_position"] for node in nodes]
    if positions != sorted(set(positions)):
        print("BAD-TABLE nodes not in path order: %s" % positions)
    for index, frame in enumerate(frames):
        parent = frame.get("parent")
        if (parent is None) != ("call_site" not in frame):
            print("BAD-TABLE frame %d: call site and parent disagree" % index)
        if parent is not None and parent >= index:
            print("BAD-TABLE frame %d listed before its parent" % index)
    for node in nodes:
        if not isinstance(node["state_id"], int):
            print("BAD-TABLE state id")


def main():
    with open(sys.argv[1], "rb") as f:
        plist = plistlib.load(f)
    files = plist["files"]

    for diag in plist["diagnostics"]:
        trace = diag.get("constraint_trace")
        if trace is None or "exploded_nodes" not in trace:
            print("NO-NODES")
            continue
        trace = constraint_trace.expand(trace)
        nodes = trace["exploded_nodes"]
        frames = trace["stack_frames"]
        check_tables(nodes, frames)
        ids = [node["id"] for node in nodes]
        print("NODES %d FRAMES %d SHARED-IDS %d"
              % (len(nodes), len(frames), len(ids) - len(set(ids))))

        steps = {step["path_index"]: step for step in trace["steps"]}
        for index, piece in enumerate(diag["path"]):
            step = steps.get(index)
            if step is None:
                continue
            if "exploded_node" not in step:
                print("%s: NO-NODE" % step_label(piece))
                continue
            node = nodes[step["exploded_node"]]
            print("%s: N%d %s %s in %s" % (
                step_label(piece), step["exploded_node"], node["kind"],
                render_location(files, node.get("location")),
                render_stack(files, frames, node["frame"])))


if __name__ == "__main__":
    main()
