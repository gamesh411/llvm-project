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
  symbols: array, the symbol table (see below), absent when the snapshots mention no symbol
  strings: array of string, every string the list entries and the symbol table name, each once
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

## Symbol table

As of the `llvm-project` commit titled "[analyzer] Record where conjured symbols of a constraint trace came from", a trace has a table of the atomic symbols its snapshots mention.
It has one entry for each symbol that is the symbol of a `symbol_ranges` or `path_condition` entry, the value of a `variables` entry of kind `symbol`, or an atom of a symbolic expression in one of them.
A symbolic expression such as `(conj_$5{int, ...}) + 1` has no entry of its own, and a reader renders it from the entries of its atoms.
Symbols that only appear inside another symbol's dump, such as the parent of a `derived_` symbol, have no entry yet.
The table is keyed by the symbol's dump in `strings`, the same string the lists use, and is sorted by that dump.

```
symbols[*]: dict
  symbol: integer, index into strings of the symbol's dump
  kind: string, one of region_value, conjured, derived, metadata, extent
  smt: integer, index into strings of the symbol's SMT-LIB term, in the encoding of smt_declarations; only when smtlib is true and the symbol has a bitvector term
  smt_signed: boolean, whether comparisons on smt are signed; present with smt
  origin: dict, only for a conjured symbol
    reason: string, why the analyzer made the symbol (see below)
    function: integer, index into strings of the function of the stack frame the symbol was made in
    frame: integer, index into stack_frames of that frame; absent when the frame has no node in exploded_nodes, such as a call the diagnostic pruned
    statement: integer, index into strings of the statement the symbol was made for, printed on one line and cut at 120 bytes with "..." appended; absent when there is none
    location: dict of line, col, file, as a node's location, the start of that statement; absent with statement
    callee: integer, index into strings of the called function's name, when statement is a call to a known function
```

`reason` is one of:

- `call_result`: the value a call returned, which the analyzer evaluated without seeing inside the callee.
  Clang writes it only for a symbol that was bound to the call at the node in which the analyzer's own conservative evaluation of that call ended, which is the node tagged "ExprEngine : Conservative eval call".
- `other`: anything else, including a call that a checker modelled, such as `malloc` under `unix.Malloc`, and values that invalidation or loop widening made.

Clang never reads a reason off the statement's text or kind.
More reasons may be added, and a reader must treat a reason it does not know as `other`.

Nothing else in the trace changes with the table: the existing keys are as before, except that `strings` gains the strings only the table names, after all the others.
A plist's `files` can gain the file of a symbol's statement when no other location names it.
Such files are added in order after the files of the diagnostic's `ExecutedLines`, so every file keeps the index it has without the table.

## Control flow graphs

Each report has one CFG per function its Bug Path runs through, with blocks and elements as arrays instead of dicts.
A CFG has a body, which does not depend on the path, and the part of it the path took.

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

`function`, `entry`, `exit` and `blocks` make up the body.
In a plist, as of the `llvm-project` commit titled "[analyzer] Keep each CFG body of a constraint trace once per plist file", each body is written once per file, in the top-level key `constraint_trace_cfgs`, next to `files`.
A trace's `cfgs` entry then names its body by index instead of holding it:

```
constraint_trace_cfgs: array, at the top of the plist, absent when no trace has a CFG
  [*]: dict of function, entry, exit, blocks; blocks is a string of their JSON in a plist CodeChecker wrote
constraint_trace.cfgs[*]: dict
  graph: integer, index into constraint_trace_cfgs
  path_blocks, path_edges: as above
```

The reports of one translation unit run through the same functions again and again, so this is where most of the size was.
On the 150-TU LLVM sample of the [LLVM run](wiki/execution-plan.md), CFGs were 87% of the trace JSON, and keeping each body once per file instead of once per report cuts the CFG bytes 6.2 times; across the whole sample it would be 6.6 times.
Clang tells bodies apart by their printed text.
CodeChecker writes its plists the same way, keeping a body once per file by object first and by content otherwise.
As of the `codechecker` commit titled "Constraint trace: write CFG blocks as JSON text in plists", CodeChecker writes a body's `blocks` as one string holding the JSON of the array above, because its plist writer spends most of a body's bytes on tags and indentation.
Over the LLVM run's plists that is 177 MB of bodies instead of 466 MB.
Clang writes `blocks` as plist arrays, and the report converter reads both.
Since `CodeChecker analyze` rewrites every plist Clang writes, the plists in a report directory have the JSON text.

A reader of a plist puts the body back into each entry, so the CFGs of a trace that CodeChecker stores, returns through `ReportDetails.constraintTrace` and the UI reads are whole, as above.
The bodies of one plist's traces are shared objects in the report converter, not copies.
A plist without `constraint_trace_cfgs`, written by a Clang from before that commit, carries whole CFGs in each trace, and the report converter still reads it.

Measured on the version 1 tmux traces before the change, the array encoding is 70.5% of the dict encoding's plist bytes.
Interning element texts in `strings` was measured too and did not pay: 2,789,048 bytes against 2,751,095 without, because few texts repeat.
On 2026-11-12, on the 191 distinct bodies of the LLVM run's largest plist (`CompilerInvocation.cpp`), splitting each element's text into its expression and its `(ImplicitCastExpr, ...)` annotation and interning both per body was measured as well.
It shrinks the bodies' JSON 2.3 times (2,521,301 to 1,073,667 bytes), but their plist only 1.27 times (6,425,801 to 5,067,667) and their zlib size 1.13 times (204,613 to 181,093), because CodeChecker's plist writer spends most bytes on tags and indentation.
That was too little for a change to every reader once bodies are kept per file, which took that plist's CFGs from 72,910,993 to 8,710,832 bytes.

## What CodeChecker stores

The report converter keeps a version 2 trace as Clang wrote it and does not expand it.
As in version 1, each step's `path_index` becomes `kind` (`event` or `control`), `index` and `order`, and `location.file` and `call_site.file` become paths.
The converter checks each trace once, at parse time, and drops a malformed one with a warning.
The symbol table is stored as Clang wrote it, with an origin's `location.file` turned into a path like the other trace locations, and trimmed by `--trim-path-prefix` with them.
A symbol table that does not read makes its trace malformed.
A trace of any other version is kept as `{"version": N}` alone.
The web UI then shows the disabled "Show constraints" toggle with an explanation that the data was recorded in an older format, and What-If answers Unknown with the same reason.
A version 1 trace stored before the change is in the database whole, and it gets the same treatment, since only version 2 is read.

## Reading a trace

Each language has one reader, and every consumer goes through it.

- Python: `codechecker_report_converter/report/constraint_trace.py`, `ConstraintTrace`.
  `symbols()` reads the symbol table, keyed by dump, with its strings read; `encode()` writes one.
  `read_graphs()` reads a plist's `constraint_trace_cfgs`, `resolve_cfgs()` puts those bodies back into a trace, and `GraphTable` keeps each body once, with JSON text blocks, when a plist is written.
  The report converter uses its `check()`, and What-If uses its `lifetimes()`, which lists every entry once with the span of nodes it holds for.
  `snapshot(node)` rebuilds a whole snapshot by replaying deltas from a checkpoint kept every 64 nodes.
  `encode()` writes a version 2 trace from whole snapshots, with Clang's matching rule, for tests and fixture derivation.
- JavaScript: `web/server/vue-cli/src/components/Report/ConstraintTrace.js`, `ConstraintTrace`.
  `symbols` and `symbol(dump)` read the symbol table, `nearestStep()` finds the Path Step nearest to a symbol's origin, and `symbolLabel()` gives the text the panel shows for a symbol.
  The UI builds a step's snapshot the first time it is shown and keeps it.
  It tells whether two steps show the same snapshot without building either, from a running hash of each node's lists checked against the raw entries, and it names path condition symbols from a change log built once.
- The Clang lit tests read it through `clang/test/Analysis/diagnostics/Inputs/constraint_trace.py`, whose `expand()` takes the plist's `constraint_trace_cfgs` too, and whose `symbols()` reads the symbol table.

## Sizes

Measured on 2026-11-11 on the inputs of the [performance evaluation](perf-evaluation.md), with the pre-change Clang at `llvm-project@385184e2a529`.

| input | plist v1 | plist v2 | stored blob v1 | stored blob v2 |
| --- | --- | --- | --- | --- |
| synthetic, 305 steps | 14,171,511 | 593,309 | 69,016 | 17,640 |
| synthetic, 605 steps | 54,693,130 | 1,180,991 | 2,659,115 | 34,723 |
| synthetic, 1205 steps | 214,996,517 | 2,358,006 | 10,827,104 | 67,914 |
| tmux 3.5a, 146 plists | 23,489,094 | 6,894,458 | 372,757 | 255,224 |

On 2026-11-12, on the whole LLVM run of the [execution plan](wiki/execution-plan.md) (3545 plists, 3928 stored reports), with CFG bodies kept once per plist file and written by CodeChecker as JSON text:

| measure | CFGs in every report | bodies once per file, Clang's plist arrays | and JSON text blocks |
| --- | --- | --- | --- |
| plist total | 1,444,433,245 | 865,313,449 | 560,384,519 |
| largest plist (`CompilerInvocation.cpp`) | 97,166,824 | 24,114,961 | 20,119,376 |
| CFG bodies in plists | most of the 87% of trace JSON | 466,278,954 | about 177,000,000 |

What CodeChecker stores is the same as before, so the path data and `getReportDetails` sizes did not change.
Plist size grows about 2.0 times per doubling of the path, against 3.9 times in version 1.
The remaining tmux bytes are mostly the CFGs and the node table's locations, which were already linear.
