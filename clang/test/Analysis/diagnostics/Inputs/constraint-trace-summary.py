#!/usr/bin/env python3
"""Print one line per event Path Step of each diagnostic in a plist file, with
the symbol ranges its Constraint Snapshot holds, so a test can FileCheck them.
Events without a snapshot are printed as MISSING, and a snapshot that does not
belong to an event in the path fails the script.
"""

import plistlib
import sys


def main():
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
            ranges = (
                "MISSING"
                if step is None
                else "; ".join(
                    "%s = %s" % (r["symbol"], r["range"])
                    for r in step["symbol_ranges"]
                )
            )
            print('EVENT "%s": %s' % (piece["message"], ranges))


if __name__ == "__main__":
    main()
