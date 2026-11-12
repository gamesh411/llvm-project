#!/usr/bin/env python3
"""Print the symbol table of each diagnostic's constraint trace, one line per
symbol, so a test can FileCheck it.

A symbol prints as `SYMBOL <dump> <kind>`, followed for a derived symbol by
`parent <dump> region <access path>`, for a region value by `name <access
path>` when it has one, and for a conjured symbol by its origin:
`<reason> "<statement>" @<file>:<line>:<col> callee <name> region <name>
globals loop @<file>:<line>:<col> in <function> frame <index>`, each part only
when the trace has it, and `frame none` when its frame is not in
stack_frames. With the optional second
argument `smt`, a symbol with an SMT-LIB term also prints `smt <term>
[signed|unsigned]`. With `types`, every symbol prints `type <type>` and, for an
address, `pointer`, after the rest, and after the symbols each symbolic
expression prints as `EXPRESSION <dump> type <type>`, with `pointer` for an
address.

Before the symbols, the table is checked against the snapshots: an atomic
symbol that a list names without an entry prints NO-ENTRY, and an entry that
no list mentions prints UNUSED-ENTRY. A symbolic expression that a list names
without a type entry prints NO-TYPE, and a type entry for a dump no list
names, or for an atom, prints UNUSED-TYPE.
"""

import plistlib
import re
import sys

import constraint_trace

# The atomic symbol a whole dump is, as in conj_$3{int, LC1, S1234, #1} or
# reg_$0<int x>. A symbolic expression starts with a parenthesis or holds an
# operator after its first symbol.
ATOM = re.compile(r"^[a-z]+_\$\d+[<{]")
OPENERS = {"<": ">", "{": "}"}


def is_atom(dump):
    match = ATOM.match(dump)
    if not match:
        return False
    closing, depth = OPENERS[dump[match.end() - 1]], 0
    for index in range(match.end() - 1, len(dump)):
        if dump[index] == dump[match.end() - 1]:
            depth += 1
        elif dump[index] == closing:
            depth -= 1
            if depth == 0:
                return index == len(dump) - 1
    return False


def mentioned(trace):
    """Every symbol dump the snapshot lists of the trace name."""
    dumps = set()
    for step in constraint_trace.snapshots(trace):
        dumps.update(entry["symbol"] for entry in step["symbol_ranges"])
        dumps.update(entry["symbol"] for entry in step["path_condition"])
        dumps.update(
            entry["value"] for entry in step["variables"] if entry["kind"] == "symbol"
        )
    return dumps


def render_location(files, location):
    return "@%s:%d:%d" % (
        files[location["file"]].rsplit("/", 1)[-1],
        location["line"],
        location["col"],
    )


def render(files, dump, symbol, smt, types=False):
    parts = ["SYMBOL", dump, symbol["kind"]]
    if "parent" in symbol:
        parts.append("parent " + symbol["parent"])
    if "region" in symbol:
        parts.append("region " + symbol["region"])
    if "name" in symbol:
        parts.append("name " + symbol["name"])
    origin = symbol.get("origin")
    if origin is not None:
        parts.append(origin["reason"])
        if "statement" in origin:
            parts.append('"%s"' % origin["statement"])
        if "location" in origin:
            parts.append(render_location(files, origin["location"]))
        if "callee" in origin:
            parts.append("callee " + origin["callee"])
        if "region" in origin:
            parts.append("region " + origin["region"])
        if origin.get("globals"):
            parts.append("globals")
        if "loop" in origin:
            parts.append("loop " + render_location(files, origin["loop"]))
        parts.append("in " + origin["function"])
        parts.append("frame %s" % origin.get("frame", "none"))
    if smt and "smt" in symbol:
        parts.append(
            "smt %s [%s]"
            % (symbol["smt"], "signed" if symbol["smt_signed"] else "unsigned")
        )
    if types:
        parts.append("type %s" % symbol.get("type", "none"))
        if symbol.get("pointer"):
            parts.append("pointer")
    return " ".join(parts)


def main():
    smt = "smt" in sys.argv[2:]
    types = "types" in sys.argv[2:]
    with open(sys.argv[1], "rb") as f:
        plist = plistlib.load(f)

    for diag in plist["diagnostics"]:
        trace = diag.get("constraint_trace")
        if trace is None:
            print("NO-TRACE")
            continue
        print("TRACE %s" % diag["description"])
        table = constraint_trace.symbols(trace)
        dumps = mentioned(trace)
        for dump in sorted(dumps):
            if is_atom(dump) and dump not in table:
                print("NO-ENTRY %s" % dump)
        for dump in table:
            if not any(dump in text for text in dumps):
                print("UNUSED-ENTRY %s" % dump)
        if list(table) != sorted(table):
            print("UNSORTED-TABLE")
        for dump, symbol in table.items():
            print(render(plist["files"], dump, symbol, smt, types))
        typed = constraint_trace.expressions(trace)
        for dump in sorted(dumps):
            if not is_atom(dump) and dump not in typed:
                print("NO-TYPE %s" % dump)
        for dump in typed:
            if dump not in dumps or is_atom(dump):
                print("UNUSED-TYPE %s" % dump)
        if list(typed) != sorted(typed):
            print("UNSORTED-TYPES")
        if types:
            for dump, expression in typed.items():
                print(
                    "EXPRESSION %s type %s%s"
                    % (
                        dump,
                        expression.get("type", "none"),
                        " pointer" if expression.get("pointer") else "",
                    )
                )


if __name__ == "__main__":
    main()
