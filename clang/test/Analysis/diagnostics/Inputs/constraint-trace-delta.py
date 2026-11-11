#!/usr/bin/env python3
"""Print how each analyzer node's snapshot changes the one before it, so a
test can FileCheck that a trace grows with the path, not with its square.

A node prints as `N<index>` followed by, for each list that changed, its name
and `+` inserted, `~` replaced, `-` removed entry counts. Before the nodes, the
trace prints `STRINGS <count>`. BAD lines report a string that the table holds
twice, a path condition entry that a later node removes, and a step whose
expanded snapshot does not match the full lists rebuilt from scratch.
"""

import collections
import plistlib
import sys

import constraint_trace

NAMES = {
    "symbol_ranges": "ranges",
    "variables": "vars",
    "path_condition": "pc",
    "smt_declarations": "decls",
}


def main():
    with open(sys.argv[1], "rb") as f:
        plist = plistlib.load(f)

    for diag in plist["diagnostics"]:
        trace = diag.get("constraint_trace")
        if trace is None:
            print("NO-TRACE")
            continue
        strings = trace["strings"]
        repeated = [s for s, n in collections.Counter(strings).items() if n > 1]
        for string in repeated:
            print("BAD duplicate string %r" % string)
        print("STRINGS %d" % len(strings))
        for index, node in enumerate(trace["exploded_nodes"]):
            parts = []
            for field, name in NAMES.items():
                delta = node.get(field)
                if delta is None:
                    continue
                if field == "path_condition" and delta.get("remove"):
                    print("BAD path condition entry removed at N%d" % index)
                parts.append(
                    "%s +%d ~%d -%d"
                    % (
                        name,
                        len(delta.get("insert", [])),
                        len(delta.get("replace", [])),
                        len(delta.get("remove", [])),
                    )
                )
            print(("N%d %s" % (index, " ".join(parts))).rstrip())


if __name__ == "__main__":
    main()
