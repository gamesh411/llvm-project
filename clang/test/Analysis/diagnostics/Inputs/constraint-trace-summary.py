#!/usr/bin/env python3
"""Print one line per event Path Step of each diagnostic in a plist file, with
one list its Constraint Snapshot holds, so a test can FileCheck it. The list
is named by the optional second argument: symbol_ranges (default),
path_condition or variables.
Events without a snapshot are printed as MISSING, and a snapshot that does not
belong to an event in the path fails the script.
"""

import plistlib
import sys


def render(field, entry):
    if field == "variables":
        return "%s = %s [%s]" % (entry["name"], entry["value"], entry["kind"])
    return "%s = %s" % (entry["symbol"], entry["range"])


def main():
    field = sys.argv[2] if len(sys.argv) > 2 else "symbol_ranges"
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
        assert all(path[i]["kind"] == "event" for i in snapshots), snapshots
        for index, piece in enumerate(path):
            if piece["kind"] != "event":
                continue
            step = snapshots.get(index)
            entries = (
                "MISSING"
                if step is None
                else "; ".join(render(field, entry) for entry in step[field])
            )
            print('EVENT "%s": %s' % (piece["message"], entries))


if __name__ == "__main__":
    main()
