"""Read a version 2 constraint trace back into the full snapshot of every
Path Step, for the test helpers next to this file.

A trace keeps one snapshot per analyzer node in `exploded_nodes`, each one
written as the change from the node before it, and keeps every string once in
`strings`. Its control flow graphs name their bodies in the plist's
`constraint_trace_cfgs`, which holds each body once per file. `expand` returns
the trace with each step carrying its node's whole snapshot, and with the
control flow graphs whole and as dicts, so that the helpers can print what a
step shows. `symbols` reads the table of the symbols those snapshots mention.
"""

LISTS = (
    "symbol_ranges",
    "variables",
    "path_condition",
    "smt_declarations",
    "caller_variables",
)


def apply_delta(entries, delta):
    """The list after `delta`: replacements and removals at positions in the
    list before it, then insertions at positions in the list after it."""
    entries = list(entries)
    for operation in delta.get("replace", []):
        entries[operation[0]] = operation[1:]
    for index in reversed(delta.get("remove", [])):
        del entries[index]
    for operation in delta.get("insert", []):
        entries.insert(operation[0], operation[1:])
    return entries


def render_variable(entry, strings):
    variable = {
        "name": strings[entry[0]],
        "value": strings[entry[1]],
        "kind": strings[entry[2]],
    }
    if len(entry) > 3:
        variable["smt"] = strings[entry[3]]
        variable["smt_signed"] = bool(entry[4])
    return variable


def render_entry(field, entry, strings, smtlib):
    if field == "smt_declarations":
        return strings[entry[0]]
    if field == "variables":
        return render_variable(entry, strings)
    if field == "caller_variables":
        # The first value is an index into stack_frames, not into strings.
        return {"frame": entry[0], **render_variable(entry[1:], strings)}
    rendered = {"symbol": strings[entry[0]], "range": strings[entry[1]]}
    if field == "path_condition" and smtlib:
        rendered["assertion"] = strings[entry[2]]
    return rendered


def snapshots(trace):
    """The full snapshot of each node, in the order of `exploded_nodes`."""
    strings = trace["strings"]
    smtlib = trace.get("smtlib", False)
    lists = {field: [] for field in LISTS}
    result = []
    for node in trace["exploded_nodes"]:
        for field in LISTS:
            if field in node:
                lists[field] = apply_delta(lists[field], node[field])
        snapshot = {
            field: [render_entry(field, e, strings, smtlib) for e in lists[field]]
            for field in LISTS
        }
        condition = snapshot["path_condition"]
        if smtlib:
            snapshot["smt_assertions"] = [c.pop("assertion") for c in condition]
        else:
            del snapshot["smt_declarations"]
        if "cfg_position" in node:
            snapshot["cfg_position"] = node["cfg_position"]
        result.append(snapshot)
    return result


def symbols(trace):
    """The trace's symbol table keyed by symbol dump, with its strings read.
    A trace from a Clang before the table has none, and gives an empty one."""
    strings = trace["strings"]
    table = {}
    for entry in trace.get("symbols", []):
        symbol = {"kind": entry["kind"]}
        for key in ("parent", "region", "name"):
            if key in entry:
                symbol[key] = strings[entry[key]]
        if entry.get("in_call"):
            symbol["in_call"] = True
        if "type" in entry:
            symbol["type"] = strings[entry["type"]]
        if entry.get("pointer"):
            symbol["pointer"] = True
        if "smt" in entry:
            symbol["smt"] = strings[entry["smt"]]
            symbol["smt_signed"] = entry["smt_signed"]
        if "origin" in entry:
            origin = dict(entry["origin"])
            for key in ("statement", "callee", "function", "region"):
                if key in origin:
                    origin[key] = strings[origin[key]]
            symbol["origin"] = origin
        table[strings[entry["symbol"]]] = symbol
    return table


def expressions(trace):
    """The types of the trace's symbolic expressions keyed by dump, as
    {"type", "pointer"}. A trace from a Clang before them has none."""
    strings = trace["strings"]
    table = {}
    for entry in trace.get("expressions", []):
        expression = {}
        if "type" in entry:
            expression["type"] = strings[entry["type"]]
        if entry.get("pointer"):
            expression["pointer"] = True
        table[strings[entry["symbol"]]] = expression
    return table


def expand_cfg(cfg, graphs):
    graph = graphs[cfg["graph"]]
    blocks = []
    for block_id, terminator, successors, elements in graph["blocks"]:
        block = {"id": block_id, "elements": [], "successors": successors}
        for text, line, parent in elements:
            element = {"text": text}
            if line:
                element["line"] = line
            if parent >= 0:
                element["parent"] = parent
            block["elements"].append(element)
        if terminator:
            block["terminator"] = terminator
        blocks.append(block)
    edges = cfg["path_edges"]
    return {
        "function": graph["function"],
        "entry": graph["entry"],
        "exit": graph["exit"],
        "blocks": blocks,
        "path_blocks": cfg["path_blocks"],
        "path_edges": [
            {"from": edges[i], "to": edges[i + 1]} for i in range(0, len(edges), 2)
        ],
    }


def expand(trace, graphs):
    """The trace with each step's full snapshot in the step. `graphs` is the
    plist's `constraint_trace_cfgs`."""
    assert trace["version"] == 2, trace["version"]
    by_node = snapshots(trace)
    steps = [{**step, **by_node[step["exploded_node"]]} for step in trace["steps"]]
    expanded = {**trace, "steps": steps}
    if "cfgs" in trace:
        expanded["cfgs"] = [expand_cfg(cfg, graphs) for cfg in trace["cfgs"]]
    return expanded
