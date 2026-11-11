# Constraint trace format, version 2

Related: [data contract](wiki/data-contract.md), [performance evaluation](perf-evaluation.md).

Version 2 replaces version 1 everywhere, as decided in the 2026-11-11 entry of the [execution plan](wiki/execution-plan.md).
A version 1 trace repeated each Path Step's whole Constraint Snapshot, so it grew with the square of the Bug Path's length.
Version 2 keeps one snapshot per analyzer node, written as the change from the node before it, and keeps every string once per report.
It grows linearly with the length of the path.

Clang writes it as of the `llvm-project` commit titled "[analyzer] Write constraint traces as per-node deltas (version 2)", behind the same `-analyzer-config emit-constraint-snapshots=true` option.

## Layout

The trace is the per-diagnostic plist key `constraint_trace`, next to `path`.

```
constraint_trace: dict
  version: 2
  smtlib: true when the snapshots carry SMT-LIB (a Clang built with Z3); absent otherwise
  steps: array, one dict per Path Step with a snapshot, in the order Clang printed the path
    path_index: integer, the step's position in the diagnostic's `path` array
    exploded_node: integer, index into exploded_nodes of the node whose snapshot the step shows
  cfgs: array, one control flow graph per function the Bug Path runs through (see below)
  exploded_nodes: array, the snapshot table, one dict per node a step names, sorted by path_position
    id, state_id, path_position, kind, location, frame: as in version 1
    cfg_position: as a version 1 step's, absent when the node has no place in a carried CFG
    symbol_ranges, variables, path_condition, smt_declarations: list deltas (see below), each absent when that list did not change
  stack_frames: array, as in version 1
  strings: array of string, every string the list entries name, each once
```

Consumers must ignore keys they do not know.
The snapshot table is keyed by node object, not by `id`: the exploded graph gives out the newest node's ID again after it reclaims a node, so two entries can have the same `id`.
Every step names a node, because every snapshot is built from one, and a node has exactly one snapshot.

## Snapshot lists

A node's snapshot has four lists.
Each is written as a delta against the same list of the previous entry in `exploded_nodes`.
The first entry's deltas are against empty lists.

```
delta: dict, each key absent when empty
  replace: array of [position, entry...], positions in the previous list
  remove: array of integer, positions in the previous list, ascending
  insert: array of [position, entry...], positions in the resulting list, ascending
```

To apply a delta, first replace the listed entries, then remove the listed positions from the highest down, then insert the listed entries in ascending order of position.
An operation is one flat array: its position followed by the entry's values.

Entries are arrays of integers, which are indices into `strings` unless noted otherwise:

| list | entry | version 1 key it rebuilds |
| --- | --- | --- |
| `symbol_ranges` | `[symbol, range]` | `{symbol, range}` |
| `variables` | `[name, value, kind]` or `[name, value, kind, smt, signed]`, where `signed` is the integer 0 or 1 | `{name, value, kind}` and, when present, `smt` and `smt_signed` |
| `path_condition` | `[symbol, range]`, or `[symbol, range, assertion]` when `smtlib` is true | `{symbol, range}`; the assertions in list order are the step's `smt_assertions` |
| `smt_declarations` | `[declaration]` | one string of `smt_declarations` |

Without `smtlib`, a step has neither `smt_declarations` nor `smt_assertions`, as in version 1 from a Clang without Z3.
The order of each rebuilt list is the version 1 order: ranges and the path condition sorted by symbol dump, variables by name, declarations by symbol ID.

Clang matches the entries of two consecutive lists by their first value, which is the symbol, the name or the declaration.
An entry kept with new values becomes a `replace`, so a narrowed range on a symbol is one operation.
When matching fails, for example because two entries share a first value or kept entries change order, the delta removes the whole previous list and inserts the whole new one.
Clang checks in assertion builds that each delta rebuilds the snapshot it describes.

The path condition only narrows along a path: a symbol's range is replaced by a narrower one and a symbol is never dropped, even once dead.
So its deltas only replace and insert, and never remove.
Each entry carries its SMT-LIB assertion, so the SMT-LIB of the path condition costs one index per change rather than a full copy per step.
Every SMT-LIB declaration and assertion text is in `strings` once per report.

## Control flow graphs

The CFGs are written once per function per report, as in version 1, with blocks and elements as arrays instead of dicts.

```
cfgs[*]: dict
  function, entry, exit: as in version 1
  blocks: array, sorted by descending ID (entry first), each [id, terminator, successors, elements]
    id: integer
    terminator: string, empty when the block has none
    successors: array of integer, -1 for an unreachable successor
    elements: array of [text, line, parent], with line 0 when the statement has none and parent -1 when absent
  path_blocks: array of integer, ascending
  path_edges: flat array of integers, [from, to, from, to, ...], sorted by edge
```

Measured on the version 1 tmux traces before the change, the array encoding is 70.5% of the dict encoding's plist bytes.
Interning element texts in `strings` was measured too and did not pay: 2,789,048 bytes against 2,751,095 without, because few texts repeat.

## What CodeChecker stores

The report converter keeps a version 2 trace as Clang wrote it and does not expand it.
As in version 1, each step's `path_index` becomes `kind` (`event` or `control`), `index` and `order`, and `location.file` and `call_site.file` become paths.
The converter checks each trace once, at parse time, and drops a malformed one with a warning.
A trace of any other version is kept as `{"version": N}` alone.
The web UI then shows the disabled "Show constraints" toggle with an explanation that the data was recorded in an older format, and What-If answers Unknown with the same reason.
A version 1 trace stored before the change is in the database whole, and it gets the same treatment, since only version 2 is read.

## Reading a trace

Each language has one reader, and every consumer goes through it.

- Python: `codechecker_report_converter/report/constraint_trace.py`, `ConstraintTrace`.
  The report converter uses its `check()`, and What-If uses its `lifetimes()`, which lists every entry once with the span of nodes it holds for.
  `snapshot(node)` rebuilds a whole snapshot by replaying deltas from a checkpoint kept every 64 nodes.
  `encode()` writes a version 2 trace from whole snapshots, with Clang's matching rule, for tests and fixture derivation.
- JavaScript: `web/server/vue-cli/src/components/Report/ConstraintTrace.js`, `ConstraintTrace`.
  The UI builds a step's snapshot the first time it is shown and keeps it.
  It tells whether two steps show the same snapshot without building either, from a running hash of each node's lists checked against the raw entries, and it names path condition symbols from a change log built once.
- The Clang lit tests read it through `clang/test/Analysis/diagnostics/Inputs/constraint_trace.py`.

## Sizes

Measured on 2026-11-11 on the inputs of the [performance evaluation](perf-evaluation.md), with the pre-change Clang at `llvm-project@385184e2a529`.

| input | plist v1 | plist v2 | stored blob v1 | stored blob v2 |
| --- | --- | --- | --- | --- |
| synthetic, 305 steps | 14,171,511 | 593,309 | 69,016 | 17,640 |
| synthetic, 605 steps | 54,693,130 | 1,180,991 | 2,659,115 | 34,723 |
| synthetic, 1205 steps | 214,996,517 | 2,358,006 | 10,827,104 | 67,914 |
| tmux 3.5a, 146 plists | 23,489,094 | 6,894,458 | 372,757 | 255,224 |

Plist size grows about 2.0 times per doubling of the path, against 3.9 times in version 1.
The remaining tmux bytes are mostly the CFGs and the node table's locations, which were already linear.
