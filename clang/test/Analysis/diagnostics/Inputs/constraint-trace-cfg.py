#!/usr/bin/env python3
"""Print the control flow graphs of each diagnostic's constraint trace, and
where each Path Step sits in them, so a test can FileCheck it.

Each graph prints the index of its body in the plist's `constraint_trace_cfgs`
after `body`, and the file prints how many bodies it holds after `BODIES`, last.
Blocks are printed as `B<id>`, with `path` when the Bug Path entered them, then
their elements as `<n>: <text> @<line> ^<parent>` with n counted from 1 as in
debug.DumpCFG, the terminator after `T:`, and the successors after `->`, `-`
standing for an unreachable one. A step's position reads `B<id>.<n>` for an
element, `B<id>.T` for the terminator and `B<id>` for the block entry; a step
without a position prints NO-POSITION.
"""

import plistlib
import sys

import constraint_trace


def render_element(index, element):
    text = "%d: %s" % (index + 1, element["text"])
    if "line" in element:
        text += " @%d" % element["line"]
    if "parent" in element:
        text += " ^%d" % (element["parent"] + 1)
    return text


def render_position(cfgs, position):
    cfg = cfgs[position["cfg"]]
    text = "%s B%d" % (cfg["function"], position["block"])
    if "element" in position:
        text += ".%d" % (position["element"] + 1)
    elif position.get("terminator"):
        text += ".T"
    return text


def step_label(piece):
    if piece["kind"] == "control":
        end = piece["edges"][0]["end"][0]
        return "CONTROL ending at %d:%d" % (end["line"], end["col"])
    return 'EVENT "%s"' % piece["message"]


def main():
    with open(sys.argv[1], "rb") as f:
        plist = plistlib.load(f)

    for diag in plist["diagnostics"]:
        trace = diag.get("constraint_trace")
        if trace is None or "cfgs" not in trace:
            print("NO-CFGS")
            continue
        trace = constraint_trace.expand(trace, plist.get("constraint_trace_cfgs", []))
        cfgs = trace["cfgs"]
        for cfg, ref in zip(cfgs, diag["constraint_trace"]["cfgs"]):
            print(
                "CFG %s entry B%d exit B%d body %d"
                % (cfg["function"], cfg["entry"], cfg["exit"], ref["graph"])
            )
            on_path = set(cfg["path_blocks"])
            for block in cfg["blocks"]:
                line = "B%d%s" % (block["id"], " path" if block["id"] in on_path else "")
                parts = [render_element(i, e) for i, e in enumerate(block["elements"])]
                if "terminator" in block:
                    parts.append("T: " + block["terminator"])
                line += ": " + "; ".join(parts) if parts else ""
                successors = ["-" if s < 0 else "B%d" % s for s in block["successors"]]
                if successors:
                    line += " -> " + " ".join(successors)
                print(line)
            print("EDGES " + " ".join("B%d->B%d" % (e["from"], e["to"]) for e in cfg["path_edges"]))

        steps = {step["path_index"]: step for step in trace["steps"]}
        for index, piece in enumerate(diag["path"]):
            step = steps.get(index)
            if step is None:
                continue
            position = step.get("cfg_position")
            print("%s: %s" % (
                step_label(piece),
                "NO-POSITION" if position is None else render_position(cfgs, position)))
    print("BODIES %d" % len(plist.get("constraint_trace_cfgs", [])))


if __name__ == "__main__":
    main()
