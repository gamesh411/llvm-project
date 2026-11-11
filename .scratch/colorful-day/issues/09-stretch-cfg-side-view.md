# 09: Stretch: CFG side view

**What to build:** When a clicked line needs more selection than the picker offers, a report reader can open a side view of the function's control flow graph, see the relevant Path Steps highlighted, and choose the location there.
Do this only after the demo in ticket 08 works.

**Blocked by:** 04

**Status:** ready-for-agent

- [x] With the analyzer option on, reports carry the control flow graph of each function on the Bug Path.
- [x] A side view renders that graph legibly, with statements readable in each block.
- [x] Blocks and elements on the Bug Path are highlighted.
- [x] Choosing an element selects the matching Path Step, and the Constraint Snapshot panel updates.
- [x] Reports with no graph data don't offer the view.
- [x] The view is checked in a real browser.

## Comments

Commits: `codechecker@b31cdd260` (graph data through store, the side view), `codechecker@4be03b7d7` (verdict wording housekeeping), and the Clang change in the `llvm-project` commit titled "Colorful Day: control flow graphs in constraint traces".

### Plist contract additions (still `version` 1)

Purely additive, behind the same `emit-constraint-snapshots` option, so `version` stays 1.
The CFGs are written once per diagnostic, inside `constraint_trace`, not per step.

```
constraint_trace:
  cfgs: array, one dict per function the Bug Path runs through, in the order the path first enters it
    function: string, the qualified name ("block" for a block, "function" for anything unnamed)
    entry, exit: integer, block IDs
    blocks: array of dict, sorted by descending ID (entry first)
      id: integer
      elements: array of dict, as -analyzer-checker=debug.DumpCFG lists them
        text: string, CFGElement::dumpToStream without the [Bn.m] helper, so `a == 0`, `p (ImplicitCastExpr, LValueToRValue, int *)`
        line: integer, expansion line of the statement; absent when it has none
        parent: integer, index of the element in the same block whose statement most closely encloses this one; absent for the statements a reader sees in the source
      terminator: string, CFGBlock::printTerminator, e.g. `if a == 0`; absent when the block has none
      successors: array of integer, in CFG order (true, false for a branch), -1 for an unreachable successor
    path_blocks: array of integer, IDs of the blocks the Bug Path entered, ascending
    path_edges: array of dict {from, to}, the block edges it took, sorted
  steps[*].cfg_position: dict, absent when the step's node has no place in a carried CFG
    cfg: integer, index into cfgs
    block: integer, block ID
    element: integer, index into the block's elements
    terminator: true when the step is at the block's terminator (then no element)
    (neither element nor terminator: the step is on entering the block)
```

- Positions come from the step's node (the same node its snapshot comes from): a `BlockEdge` out of a block with a terminator sits at that terminator, a fall-through edge or `BlockEntrance` at the destination block's entry, anything else at the element whose statement is the node's `getStmtForDiagnostics()`, walking up the `ParentMap` until one matches, or at the terminator if that statement is it.
- An "Assuming" event can sit at the condition's element (`if (a == 0)` in `branch`, where the node is the condition's `PostStmt`) or at the terminator (`if (flag)` in the callee, where it is a `BlockEdge`). Both are what the node really was; the lit test pins both.
- Visited blocks and edges are collected in `recordPathHistory`, which already walks the whole bug path once. Autosynthesized bodies (body farms) are skipped, since there is no source to match.
- A callee that `removeUnneededCalls` prunes keeps its CFG, but no step points into it.
- `constraint-snapshots-cfg.c` with `Inputs/constraint-trace-cfg.py` covers a branch, a call (caller first, callee exit on the path, caller exit not) and a loop (one block list, three iterations at one terminator). It was red before the change. `dev-loop.sh lit` runs it.

### CodeChecker contract

- No API change: `ReportDetails.constraintTrace` already returns the stored JSON verbatim.
- The parser and `convert()` returned `{version, steps}` only, so `cfgs` was dropped on store (the functional test failed with `KeyError: 'cfgs'` first). Both now keep every top-level trace key; per-step keys were already copied through.
- New fixture `no_cfgs/`, derived by `dev-loop.sh fixture` from `with_snapshots` with `cfgs` and every `cfg_position` removed: what a Clang before this change wrote, and what reports stored before it hold. `test_report_stored_without_control_flow_graph` stores it; `test_control_flow_graph_survives_store` checks the graph and positions of `with_snapshots` against hand-derived lines of `demo/two-path.c`.
- `dev-loop.sh fixture` regenerated all plists. `no_snapshots` changed only in `clang_version` and was restored, the others gained the graph data.

### Added report size (tmux 3.5a, whole project, same run as `dev-loop.sh demo`)

| | plist bytes, 146 plists |
| --- | --- |
| emission off (ticket 08) | 1,481,363 |
| emission on, ticket 08 | 17,174,536 |
| emission on, with CFGs | 23,053,531 |

- The CFGs add 5,881,343 bytes: 5,612,377 in `cfgs` and 268,966 in step `cfg_position`s, counted from the raw plist text. That is 34% on top of ticket 08's emission, 15.6 times the size with emission off.
- 30 path-sensitive reports carry 110 CFGs, about 51 KB of plist per CFG and 196 KB per report. The largest file gained 586 KB.
- The bulk is XML overhead on the linearized elements (every subexpression is a dict). Once per file instead of once per report would help only where reports share functions; a compact element encoding (an array per element) would help everywhere. Neither was done.

### Web UI

- `ControlFlowGraphView.vue`, no new npm dependency and no change to the CSP. Blocks are HTML cards in one column, entry first, in the plist's descending-ID order, which roughly follows the source. Edges are an inline SVG beside them: an edge to the next card down is a short arrow, every other edge runs in a lane of a left gutter, lanes assigned shortest span first so nested edges do not cross. Branch edges are labelled T and F. Measured from the cards' offsets with a `ResizeObserver`.
- Highlighting: blocks the Bug Path entered have a 2px step-blue border, the others are greyed; taken edges are 2px step-blue, the others 1px grey; rows with Path Steps have the bubble's light blue; the selected step's row has the selected-line yellow with the amber bar.
- By default a block lists only statements without a `parent` (what the reader sees in the source), and steps on hidden subexpressions count for their statement. "Subexpressions" shows every element with its DumpCFG number.
- A row's steps go through `oneChoicePerSnapshot`, the rule line selection already used (extracted from `pathStepsOnLine`). One choice selects it with `revealPathStep`, which is `selectStepByOrder`'s select-and-scroll without the line re-resolution, so the highlighted row stays the clicked one. Several open `PathStepPicker`, titled `B5 terminator` or `B5.4` instead of `Line 7`; the picker's `line` prop became `title`. A row with several choices reads `3 steps`, or `3 of 3 steps` when one of them is selected.
- Entry points, only when the trace has `cfgs`: a "CFG" button in the snapshot panel header (icon-only below 1280px, like the app bar), and "Choose in the control flow graph" at the foot of a line's picker. The view opens on the function of the selected step, or of the picker's steps, with a function selector when there are several. It closes with the report, and with "Show constraints".
- The view floats over the right part of the source column (`clamp(min(100%, 440px), 58%, 640px)`), so opening it reflows neither the code and its arrows nor the panel. Where the source column is under 600px it covers it whole (container query), rather than leave a sliver of line numbers.

### Housekeeping: verdict at the anchor step

When the first dead step is the anchor, the verdict read "This path is infeasible with `a == 0` at Step 1. It dies at Step 1, the first step ...".
It now reads "This path is infeasible with `a == 0` at **Step 1**. It dies right there, the first step whose path condition contradicts it.", with the anchor's step name as the select button. Other cases are unchanged. Separate commit.

### Traps

- `CFGElement::dumpToStream(OS, /*TerminateWithNewLine=*/false)` still ends statement elements (`return *p;`, `int i = 0;`) with a newline; the text is right-trimmed.
- Again Vue's whitespace condensing: a `<template v-else>` that starts with an interpolation dropped the space in "`flags == 0`at Step 1". The anchor text is now a plain interpolation after the `</code>`, which keeps it.
- In zsh, `rm -rf dir/* && cp ...` on an empty `dir` fails on the unmatched glob, and the `&&` chain stops silently there.

### Test results (2026-11-11)

- `dev-loop.sh lit`: 5 passed, 1 unsupported (no-z3), with the new `constraint-snapshots-cfg.c`. `clang/test/Analysis`: 1266 tests, the only failure the user's untracked `bstring-UninitRead-partial-init.c`. That full run was before the last edit, which only rewords the option's description in `AnalyzerOptions.def`; `lit` (including `analyzer-config.c`) passed after it.
- `dev-loop.sh functest`: 30 passed (28 before); the two new tests were written first and the graph one failed before the parser change.
- `store` 7/7. `report_viewer_api` 66/67, the known Clang 14 expectation in `test_get_run_results_checker_id_and_file_path`. Server unit: 98 passed (`test_ccldap.py` excluded). Report-converter unit: 136 passed. No tracked files changed by the runs.
- `clang-format-diff` on the C++ change, `pycodestyle` and `pylint` 10.00 on `plist.py` and the functional test, `pycodestyle` on the lit helper, `eslint` on the five touched UI files: clean.

### Verification

Screens in `/Users/efulop/colorful-day-env/screens/`, driven with `chrome-devtools-axi` on a fresh `dev-loop.sh demo` server (two-path report 1, tmux report 5), plus `demo/loop.c` stored as report 33 and the `no_cfgs` fixture as report 34:

- `09-tmux-cfg-1400.png`: Step 1 selected, "CFG" opens `grid_string_cells` (43 blocks, 61 edges) at B39, the `lastgc != ((void *)0)` row selected.
- `09-tmux-cfg-step7-1400.png`: a click on the `if flags & 1` terminator selects Step 7, the source scrolls to line 1072, the panel shows Step 7.
- `09-tmux-cfg-dead-step-{1400,900}.png`: `flags == 0` at Step 1, then the verdict's Step 7 button moves the graph selection too.
- `09-tmux-cfg-subexpressions-1400.png`: every element; Step 8 sits on the `*lastgc` load.
- `09-loop-picker-{1400,900}.png`: line 7's picker with "Choose in the control flow graph"; `09-loop-cfg-1400.png`: the graph it opens; `09-loop-cfg-picker-{1400,900}.png`: the `if i == 2` terminator offers its three iterations in the same picker, titled "B5 terminator"; `09-loop-cfg-picked-{1400,900}.png`: the third, `i = 2`, in the panel, the row reading "3 of 3 steps".
- `09-two-path-cfg-900.png` and `09-two-path-verdict-at-anchor-1400.png`: the housekeeping wording.
- `09-no-cfgs-1400.png`: a report whose trace has no graph shows no "CFG" button (checked in the DOM too); the line picker's footer has the same condition.
- Turning "Show constraints" off closes the view (DOM check).
