# 10: Stretch: exploded graph view

**What to build:** When the control flow graph can't resolve a location, for example one statement reached in several calling contexts, a report reader can open a readable view of the part of the exploded graph along the Bug Path and choose the exact analyzer state.
Do this only if time remains after ticket 09.

**Blocked by:** 09

**Status:** resolved

- [x] The view is limited to the analyzer states relevant to the Bug Path, so it stays readable on a real report.
- [x] Each state identifies its calling context and source location.
- [x] Choosing a state selects the matching Path Step and updates the Constraint Snapshot panel.
- [x] The added report size is measured on the real report from ticket 08.
- [x] The view is checked in a real browser.

## Comments

Commits: `llvm-project@11efdf0713b6` (Clang emission, lit test, demo, dev loop), `codechecker@06fde7aaa` (parser, side view, fixtures, tests).

### Plist contract additions (still `version` 1)

Purely additive, behind the same `emit-constraint-snapshots` option.
Only the nodes that Path Steps' snapshots came from are emitted, not the graph and not a state dump.

```
constraint_trace:
  exploded_nodes: array, one dict per node a step's snapshot came from, sorted by path_position
    id: integer, ExplodedNode::getID(); the trimmed bug path graph keeps the original IDs, so they match -analyzer-dump-egraph
    state_id: integer, ProgramState::getID()
    path_position: integer, the node's position on the bug path counting every node from the root,
      so the gap to the previous entry is the nodes without a step; the last entry is the error node
    kind: string, ProgramPoint::getProgramPointKindName, e.g. CallEnter, BlockEdge, PostStmt, PreLoad
    location: {line, col, file}, a plist location (file indexes `files`); absent when the node has no statement
    frame: integer, index into stack_frames of the node's innermost frame
  stack_frames: array, one dict per stack frame those nodes are in, each after its parent
    function: string, qualified name, as cfgs[*].function
    parent: integer, index of the caller's frame; absent for the top frame
    call_site: location of the call that entered the frame; absent for the top frame
  steps[*].exploded_node: integer, index into exploded_nodes
```

- The location is the node's `getStmtForDiagnostics()`; a fall-through `BlockEdge` has none, so it uses the destination block's first statement or terminator. A branch `BlockEdge` sits at its `if`, not at the condition.
- Steps that share a snapshot share a node: `Calling` and `Entered call` both name the CallEnter node in the caller, and a control edge names the node at its end, so the edges into an "Assuming" line usually share its node.
- A frame is keyed by `StackFrame::getID()`, so two calls of one function are two frames with different call sites; that is what tells `if (flag)` in `demo/several-contexts.c` apart, where the line and the CFG element are the same.
- `constraint-snapshots-egraph.c` with `Inputs/constraint-trace-egraph.py` covers two calls of one function and a one-frame path, and checks the table invariants; it was red before the change. `dev-loop.sh lit` runs it.

### CodeChecker contract

- No API change. Plist file indices do not survive storage, so the parser turns every `location.file` and `call_site.file` into the file's path, and `convert()` turns them back into indices of the plist it writes, adding a file only a call site names to `files`.
  So in `ReportDetails.constraintTrace` these `file` values are path strings, unlike in the plist. A path is not trimmed by `--trim-path-prefix`; the UI shows only its base name.
- Fixtures: `several_contexts/` from `demo/several-contexts.c`, and `no_exploded_nodes/` derived from `with_snapshots` minus the node data (what the ticket 09 Clang wrote). `no_cfgs/` now also drops the node data, which a Clang before ticket 09 did not write either. `no_snapshots` and `no_cfgs` changed only in `clang_version` and were restored.
- Tests: `test_exploded_nodes_tell_calling_contexts_apart` and `test_report_stored_without_exploded_nodes` (functional, written first, the first failed on an integer `file`), and `test_trace_locations_survive_conversion` (report-converter unit; fails with `KeyError` when `convert()` does not add the trace's files, checked by mutation).

### Added report size (tmux 3.5a, whole project, same run as `dev-loop.sh demo`)

| | plist bytes, 146 plists |
| --- | --- |
| emission off (ticket 08) | 1,481,363 |
| emission on, with CFGs (ticket 09) | 23,053,531 |
| emission on, with exploded nodes | 23,491,392 |

- The nodes add 437,861 bytes, 1.9% on top of ticket 09, so emission is now 15.9 times the off size.
- Counted from the plist text: 341,120 bytes in `exploded_nodes` (674 nodes over 30 reports, about 22 per report), 19,506 in `stack_frames` and 74,843 in the 1,278 per-step `exploded_node` keys. About 14.6 KB per report.

### Web UI

- `ReportSideView.vue` is the shell extracted from ticket 09's graph view: header with title and close, toolbar, scroller, legend swatches, and `side-view-choice`, the blue and selected-yellow row states. `ControlFlowGraphView.vue` now renders inside it with no visible change (`10-tmux-cfg-still-works-1400.png`). No new npm dependency, CSP unchanged.
- `ExplodedGraphView.vue`, "Analyzer states": the nodes in path order, grouped by consecutive stack frame. A group's header is the stack outermost first, `several_contexts › take called at several-contexts.c:13`, and groups are indented by depth. A state row shows `#id`, the program point kind, `file:line:col` and its step label; the tooltip adds the state ID and the stack. Between rows, "N nodes without a Path Step". The toolbar says "9 of 77 nodes".
- Choosing a state goes through `oneChoicePerSnapshot` and `revealPathStep` like the CFG view, and several choices would open `PathStepPicker` titled `State #id`. In practice one node always gives one choice, since equal nodes give equal snapshots.
- Entry points, only when the trace has `exploded_nodes`: a "States" button in the snapshot panel header beside "CFG" (icon only below 1280px), and "Choose by analyzer state" at the foot of a line's picker. Opening one side view closes the other. It closes with the report and with "Show constraints", like the CFG view.
- `demo/README.md` has an optional Part 3, and `dev-loop.sh demo` also stores `several-contexts.c` as `colorful-day-contexts` (report 33 on a clean server), after tmux so reports 1 and 5 keep their IDs.

### Traps

- `suppress-null-return-paths` (on by default) drops a null dereference whose null came back from an inlined call's return, so the demo nulls the pointer through an out-parameter. Calls whose only events are "Assuming" on untracked values are pruned, so a simpler two-call example showed no callee steps at all.
- The CFG rows lost their blue and yellow states for one build, because a Python string replace on the template missed after re-indenting and nothing failed. Only the browser check caught it.
- One `functest` run, straight after a `-k` run with a failing test, failed every test in setup with "Failed to add the product to the test server!". The next three runs passed 32/32. Not reproduced, cause not found.
- Not done: the `emit-constraint-snapshots` description in `AnalyzerOptions.def` does not mention the nodes.

### Test results (2026-11-11)

- `dev-loop.sh lit`: 6 passed, 1 unsupported (no-z3). `clang/test/Analysis`: 1267 tests, the only failure the user's untracked `bstring-UninitRead-partial-init.c`. That full run was before clang-format reflowed three statements, after which `lit` passed again.
- `dev-loop.sh functest`: 32 passed (30 before), twice in a row after the flake above.
- `store` 7/7. `report_viewer_api` 66/67, the known Clang 14 expectation. Server unit: 98 passed (`test_ccldap.py` excluded). Report-converter unit: 137 passed. No tracked files changed by the runs.
- `clang-format-diff` on the C++, `pycodestyle` and `pylint` 10.00 on `plist.py` and the functional test, `pycodestyle` on the unit test and lit helper, `eslint` on the Report components, `shellcheck dev-loop.sh`: clean.

### Verification

Screens in `/Users/efulop/colorful-day-env/screens/`, driven with `chrome-devtools-axi` on a `dev-loop.sh demo` server:

- `10-contexts-line5-picker-1400.png`: line 5 of `several-contexts.c` offers Step 3 and Step 8, with "Choose by analyzer state".
- `10-contexts-states-1400.png`: the view it opens; the two `take` frames are told apart by call sites 13 and 14.
- `10-contexts-state-picked-{1400,900}.png`: a click on `#158 BlockEdge` selects Step 8; the panel shows "Assuming 'flag' is 0" and the bubble is marked.
- `10-tmux-states-1400.png`: `grid.c:1073`, 13 of 285 nodes, Step 1 selected. `10-tmux-states-step7-900.png`: a click on `#3251` selects Step 7.
- `10-tmux-cfg-still-works-1400.png`: the CFG view after the shell extraction.
- `10-no-exploded-nodes-1400.png`: the `no_exploded_nodes` fixture, stored briefly as report 34, shows only "CFG" in the panel header (checked in the DOM too). A final clean `dev-loop.sh demo` removed it.

