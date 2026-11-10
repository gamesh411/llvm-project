# 04: Branch steps and line selection

**What to build:** A report reader can inspect the Constraint Snapshot at control-flow Path Steps and can select a step by clicking its source line.
When a Target Location matches several Path Steps, such as loop iterations, a small picker lets the reader choose one.

**Blocked by:** 02

**Status:** ready-for-agent

- [x] Control-flow Path Steps carry a Constraint Snapshot in the plist.
- [x] When edge optimization merges control-flow pieces, the merged piece keeps the snapshot of its later analyzer node.
- [x] Clicking a source line on the Bug Path selects its Path Step and updates the side panel.
- [x] A Target Location matching several Path Steps opens a picker that identifies each one.
- [x] Clicking a line that is not on the Bug Path leaves the current selection unchanged and tells the reader why.
- [x] A Clang lit test covers a branch and a loop, and the selection behavior is checked in a real browser.

## Comments

### Plist contract additions (still `version` 1)

Purely additive, so `version` stays 1.
`constraint_trace.steps` now also has one dict per control-flow piece, with `path_index` pointing at that `control` element of `path` and the same keys as an event step (`symbol_ranges`, `variables`, `path_condition`).

- A control piece carries the snapshot of the analyzer node at its end, so a step shows what held on arriving at the edge's target line.
  While the path is built backwards, `PathDiagnosticConstruct::EdgeEndNode` remembers the node that set `PrevLoc`, and `addEdgeToPath` (now a `PathDiagnosticBuilder` member) gives the new edge that node's snapshot.
- Every optimization that merges two edges goes through `mergeNextEdgeInto`, which keeps the later piece's end and its snapshot (rules I and II and the ObjC fast-enumeration rule).
  `simplifySimpleBranches` already keeps the later piece.
  `addContextEdges` copies the split piece's snapshot to the new context edge, and to a previous edge it extends.
- `constraint-snapshots-control.c` covers a branch, a loop (the `if` inside it is reached three times with `i` 0, 1, 2) and a merged edge.
  With `mergeNextEdgeInto` changed to keep the earlier snapshot, the merged edge shows `x = 1` instead of `x = 4` and the test fails (checked by building that mutation).
- Only the Extensive scheme (plist) adds edges.
  The `Minimal`/`Everything` control pieces from `generateMinimalDiagForBlockEdge` get no snapshot; no output that carries the trace uses them.

### CodeChecker contract additions

- Steps keep `{"kind", "index"}`; `kind` is now `event` or `control`.
  A control step's `index` is the position of its edge's end in `bug_path_positions`, which is `ReportDetails.executionPath[index]` in the API.
- Storage splits events from positions and loses their interleaving, so every step also gets `order`: its `path_index` in the original Clang plist, i.e. its place on the Bug Path.
  `convert()` writes `order` back into the plist steps and the parser keeps an existing `order`, so it survives the store round trip.
- `__get_bug_path_positions` now also returns which position each control piece ends at, and `convert()` records which edge it writes for each position, so both directions use the same mapping.
- `test_control_steps_survive_store` and `test_steps_keep_their_bug_path_order` check this through `CodeChecker store` and `getReportDetails`.

### Web UI

- Line selection only runs while "Show constraints" is on: the click handlers return immediately otherwise, and the line decorations and arrow click-through CSS are scoped to the toggle.
  Clicking a line or its line number with the toggle on selects the line's Path Step; with several, a picker (`PathStepPicker.vue`) opens at the click.
- Picker rows: `Step N` and the message for events, `Arrow after step N` and `Reaches line L, column C` for control steps, plus the variables whose values differ between the rows (`i = 0`, `i = 1`, ...), which is what tells loop iterations apart.
- Path Steps on one line with an identical snapshot (the edges into an `if` and into its condition, and the "Assuming" event there) are one choice, the event if there is one, because they would show the same panel.
  On `two-path.c` the lines tried (9 and 11) select directly; the picker appears on `loop.c` lines 6 and 7.
- A line that is not on the Bug Path keeps the selection and shows a small floating note at the bottom of the source view for 4 seconds.
- A selected control step highlights its line, since it has no bubble to mark.
- New demo file `demo/loop.c`; store it with `DEMO=.../demo/loop.c RUN_NAME=colorful-day-loop dev-loop.sh analyze` and `... store`.

### Traps

- Line numbers drifted 2px per step bubble from the text below it: the bubble's bottom margin was outside the height CodeMirror measured for the block widget.
  A `flow-root` widget container fixes it (visible in every earlier screenshot as a gutter offset).
- Even so, a click resolves its line from the clicked `.cm-line` element (`posAtDOM`), not from coordinates, which go through CodeMirror's height estimate.
- The jsPlumb arrow SVG sits over the code and swallows clicks on it; in constraints mode it gets `pointer-events: none`.
- In `<script setup>`, a ref named `pathStepPicker` made `<path-step-picker>` resolve to the ref instead of the component; the only sign was eslint's unused-import error.
- `mass_store_run` parses the plist again on the server, so parser changes need a server restart (`dev-loop.sh stop` and `server`) before a manual store shows them.
- Driving clicks in chrome-devtools-axi: `page.click(selector)` has zero coordinates, which CodeMirror maps to line 1, and a synthetic `MouseEvent` without `detail: 1` takes a different mouse-selection path.
  The checks used `mousedown`/`mouseup`/`click` at the line's coordinates with `detail: 1`.
- At 1100px the panel covers the right end of bubbles on files with lines longer than the editor; the editor scrolls horizontally, as it does without the panel.

### Test results (2026-11-10)

- `dev-loop.sh lit`: 3/3 (with the new `constraint-snapshots-control.c`). `clang/test/Analysis`: 1262 of 1263 not failing; the failure is the user's untracked `bstring-UninitRead-partial-init.c`.
  `func-mapping-test.cpp` failed until `dev-loop.sh clang` rebuilt `clang-extdef-mapping`, as noted in ticket 02.
- `dev-loop.sh functest`: 7 passed.
- `store`: 7 passed in two runs; one earlier run, straight after `functest`, failed `test_same_headers` and `test_store_stats` (3 clang-tidy reports instead of 6, log `/Users/efulop/colorful-day-env/logs/webtests-store.log` was overwritten by the rerun). Not reproduced, cause not found.
- `report_viewer_api`: 66 passed, 1 failed (the Clang 14 expectation from ticket 03).
- report-converter unit: 136 passed. `pycodestyle` and `pylint` (10.00) on `plist.py` and the functional test, `eslint` on the three Vue files, `clang-format-diff` on the C++ change: clean.

### Verification

Screens in `/Users/efulop/colorful-day-env/screens/`, driven by `chrome-devtools-axi` with clicks at the line's coordinates:
`04-off-1400.png` (toggle off; clicking a Bug Path line changed nothing), `04-picker-{1400,1100,900}.png` (`loop.c` line 7, three rows told apart by `i`), `04-control-step-{1400,1100}.png` (third row picked: panel shows "Arrow after step 5", line highlighted), `04-offpath-hint-{1400,1100,900}.png` (off-path line, selection kept), `04-two-path-branch-1400.png` (branch line selects its event directly), `04-control-step-two-path-1400.png` (control-only line 11 selects "Arrow after step 2").
