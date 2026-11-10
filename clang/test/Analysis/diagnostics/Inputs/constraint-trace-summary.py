#!/usr/bin/env python3
"""Print one line per Path Step of each diagnostic in a plist file, with one
list its Constraint Snapshot holds, so a test can FileCheck it. The list is
named by the optional second argument: symbol_ranges (default), path_condition
or variables. Only events are printed unless the third argument is "control",
which adds the control-flow pieces, labelled by their end position.
Steps without a snapshot are printed as MISSING, and a snapshot that does not
belong to an event or control piece in the path fails the script.
"""

import plistlib
import sys


def render(field, entry):
    if field == "variables":
        return "%s = %s [%s]" % (entry["name"], entry["value"], entry["kind"])
    return "%s = %s" % (entry["symbol"], entry["range"])


def control_label(piece):
    end = piece["edges"][0]["end"][0]
    return "CONTROL ending at %d:%d" % (end["line"], end["col"])


def main():
    field = sys.argv[2] if len(sys.argv) > 2 else "symbol_ranges"
    include_control = len(sys.argv) > 3 and sys.argv[3] == "control"
    with open(sys.argv[1], "rb") as f:
        plist = plistlib.load(f)

    for diag in plist["diagnostics"]:
        trace = diag.get("constraint_trace")
        if trace is None:
            print("NO-TRACE")
            continue
        print("TRACE version", trace["version"])

        path = diag["path"]
        snapshots = {step["path_index"]: step for step in trace["steps"]}
        assert all(
            path[i]["kind"] in ("event", "control") for i in snapshots
        ), snapshots
        for index, piece in enumerate(path):
            if piece["kind"] not in ("event", "control"):
                continue
            if piece["kind"] == "control" and not include_control:
                continue
            step = snapshots.get(index)
            entries = (
                "MISSING"
                if step is None
                else "; ".join(render(field, entry) for entry in step[field])
            )
            label = (
                control_label(piece)
                if piece["kind"] == "control"
                else 'EVENT "%s"' % piece["message"]
            )
            print("%s: %s" % (label, entries))


if __name__ == "__main__":
    main()
