# 08: "This path requires" list

**What to build:** A section of the panel lists everything the Bug Path demands, grouped by where each requirement comes from, so a report reader can ask which one is unrealistic and go to the code that assumed it.

**Blocked by:** 02, 04

**Status:** resolved

- [x] The section does not depend on the selected Path Step and reads the accumulated path condition of the last Path Step.
- [x] Rows are grouped from the symbol table: entry inputs (region values rooted in a parameter of the outermost frame, a global or the outermost `this`), call results, replaced values (invalidation, widening and symbols derived from them), and other.
- [x] Entry inputs come first.
- [x] Each row shows the label or name, the range, the Path Step whose node last changed it as a link, and that step's function.
- [x] A trace without the symbol table shows the list ungrouped.
- [x] A jest test covers the grouping and the "last changed at" step.
- [x] Verified in a browser at 1400 and 900 pixels on the tmux demo report and on an LLVM report from the triage study decided by entry inputs (cases 6, 27 or 29).

## Comments

2026-11-13, ticket 08 worker.

Commits: `codechecker@08cd17806`, `cfdb0827b`, `8414ea383` (the Unknown spacing test, the list with the control step rename, docs).
No Clang, server, API or Thrift change, so the server was not restarted.

### Where the section sits, and how it relates to the accumulated path condition

- Decision: the panel gets two toggle buttons under the step line, **This step** (Known here and the accumulated path condition, exactly as before) and **Whole path N** (the requires list, headed "This path requires"). One half shows at a time, and the choice stays across steps.
- Why: the accumulated path condition of the last step is the same data as the list, so on one screen the last step would show every row twice. Showing the two halves one at a time removes the duplicate by layout and keeps the accumulated section's per-step tags (new, narrowed, dropped) at the last step. The list needs no "hide" logic at the last step.
- Rejected 1: a third section in the scroll area, between Known here and the accumulated condition. In the browser it sat below the fold at 1400 x 1000 (the header showed, the rows did not) and a long list pushed the accumulated condition out of reach.
- Rejected 2: a collapsible section. A closed section hides the feature the ticket is for, an open one repeats the accumulated rows at the last step.
- Rejected 3: at the last step, the accumulated section shows a pointer instead of its rows. It loses the tags that step carries and needs an equality test between two lists. Written, run in the browser, then removed.
- What-If stays put: its top is at y = 828 at 1400 px and y = 764 at 900 px in a 1000 px window, on both halves, the same as before the change. The toggle row costs the snapshot area 28 px at 900 px (one row; the two buttons share it with the labels "This step" and "Whole path", since "This path requires" did not fit beside the other at about 230 px and wrapped to two rows) and 28 px at 1400 px.
- The "Whole path" half has the full height of the scroll area, so a long list (case 6: 19 rows, 2,354 px of content) scrolls on its own, and the shadow shows it.
- Room for ticket 09: a row is the name, then `.panel-value` with the range and its tags, then a line for where it was last set. A value beside the range goes in `.panel-value`, which has the room; nothing is built for it.

### What the reader does (`ConstraintTrace.requirements()`)

- Source: the path condition of the last Path Step (the last by Bug Path order). Independent of the selected step.
- Groups, in this order, each only when it has rows: Entry inputs, Call results, Replaced values, Other. No symbol table: one list, key null, `grouped` false.
- Classification, by the symbol's entry: a `region_value` is an entry input when it has a `name` (Clang names a region value only for a parameter, a global or `this`, or what they point to), or when it has none and its dump has no `conj_$` or `derived_$` (memory reached through a call's result is not an entry input); a `conjured` symbol goes by `origin.reason` (call_result: call result, invalidation and loop_widening: replaced, else other); a `derived` symbol goes by its parent; extent and metadata are other. This reads the dump only to tell where memory comes from, never to make a name, which the contract forbids.
- An expression has no entry. It goes by its atoms when they all agree, so `m + n` of two entry inputs is an entry input, and is other when they differ or the expression cannot be read. Not in the ticket; chosen because case 29's decisive row is that expression.
- Each row has `name`, `range`, `dropped` (no range at the last step, as the accumulated section tags it), and `changedAt`: `{ order, function, silent, exact }`. `changedAt` is the first Path Step in Bug Path order whose node is at or after the last node that inserted or replaced the entry, found from the deltas alone (no snapshot is built). `silent` is whether that step is one of `silentChanges()`; `exact` is whether its node is the changing node. When it is not, the analyzer assumed it at a node with no step of its own, and the panel says "last set before" that step. Case 6 is this case: the `?:` on line 2771 has no step, so `SuperLoc` reads "last set before Step 7".
- A silent step reads "assumed with no event at" and its link is to that control step, whose panel then says "Assumed, no event".
- The link text is the label the reader sees for that step (`resolveStep`), so an edge reads "Edge after Step 1". The function is the step's frame, written as the frame headings write it.
- Rows: named first, then natural sort, as the accumulated section.

### The two small fixes

- "at Step 10.n names 2 values": already fixed by the ticket 06 worker, which put `{{ " " }}` before the reason's text. Checked in the browser, the DOM reads `at Step 10.<!----> <code ...>n</code> names 2 values`, and the screenshot `t08-unknown-space-1400.png` shows the gap. The ticket 06 screenshot predates the fix. A test now guards it: `WhatIfSection.test.js` renders the section on the server side with `vue/server-renderer` (the jest setup has no DOM, and the generated API module is mocked) and fails without the interpolation (checked by removing it).
- "Arrow after step 2": now **Edge after Step 2** and **Edge before Step 1**, one function `controlStepLabel` in `ConstraintTrace.js`, used by `Report.vue`, tested in jest. "Edge" is the word the CFG view and the glossary use for a control step, and the capital S matches "Step 3". Rejected: "After step 2" (reads wrongly in "dies at ...") and "Between steps 2 and 3" (wrong for a step after the last event). Every label of a control step comes from that one function: the picker rows, the panel heading, the What-If verdict ("It dies earlier, at Edge after Step 2", seen on tmux report 325), and the panel's links. Docs updated; older tickets and screenshots keep the old name as history.

### Verification

- jest 127 in 7 suites (new: 8 in `ConstraintTrace.test.js` for the requires list, 1 for the label, 1 in the new `WhatIfSection.test.js`), eslint clean, functest 46 passed, pycodestyle clean, pylint 10.00. mypy reports 19 errors, all missing library stubs or modules in this venv (`yaml`, `semver.version` and so on); no Python file changed, so these are the environment's. The Clang lit suite was not run, since nothing in Clang changed.
- Browser, `/Users/efulop/colorful-day-env/screens/`, `t08-*`, at 1400 and 900 px (window height 1000), each with a `-step` companion showing the other half; no element of the panel overflows at either width, the list's rows do not clip, and What-If's position is unchanged:
  - `t08-two-path-requires-1400/900.png` (report 291): `a` not 0 dropped, last set before Step 1; `b` not 0 dropped, last set at Step 2.
  - `t08-caller-requires-1400/900.png` (report 292, Step 10): `g`, `h`, `m` and `top::n` under Entry inputs, each linked to the step in its function.
  - `t08-tmux-requires-1400/900.png` (report 325, grid.c:1073): nine entry inputs, `gd` non-null, `lastgc` null, then the expressions of them, and the silent edge after Step 2 for `gd->linedata`.
  - `t08-llvm-case6-requires-1400/900.png`, `t08-llvm-case27-...`, `t08-llvm-case29-...`, below.
  - `t08-unknown-space-1400.png`, `t08-edge-label-1400.png` for the two fixes.
- The LLVM cases came from analyzing the three TUs again (`SemaExprObjC.cpp`, `CheckExprLifetime.cpp`, `APInt.cpp`) with the current Clang, `-DNDEBUG` database of the first run, z3 refutation on, stored as `t08-llvm` (reports 356, 374, 370), script and log in `/Users/efulop/colorful-day-env/t08/`.

### What the LLVM cases show (can a reader spot the unrealistic requirement?)

- Case 6 (report 356, `SemaExprObjC.cpp:2772`): yes, and it is the first row. Entry inputs: `SuperLoc` 0 (label `SuperLoc.ID`), `this` non-null, and `P` null, which is the silent edge after Step 1 in `ActOnSuperMessage`. `SuperLoc` is the first row of the first group, read as 0, with the function it was assumed in, `BuildClassMessage`. The study asked "what does this path require of the entry function's inputs", and this is that list. The "last set before Step 7" link goes to the call event whose code is the `SuperLoc.isValid()` conditional just above it. The study's other half of the hinge, the null `ReceiverTypeInfo`, is in the event itself.
- Case 29 (report 370, `APInt.cpp:1363`): yes. Entry inputs: `n` not 0, `v` non-null, `m + n` 0, and `Val` 0 from `countl_zero`. `m + n` is the compound entry the study could not name, now in the group of entry inputs because both atoms are. The reader sees the wrap requirement without a model. A concrete example (ticket 09) would add `m = 4294967295`, `n = 1`.
- Case 27 (report 374, `CheckExprLifetime.cpp:1450`): partly. The requirement `LK == 7` is a row and is readable ("value from `std::memcpy(&R, this->Data, sizeof (R)) & 7`", 7), but it is under Other, not Entry inputs: its symbol comes from a call a checker modelled (reason `other`), which the groups do not call a call result, so the "which caller can produce it" part of the study's question is not answered by the grouping. The only entry input is `Entity->Kind` 22.

### Open points

- At 900 px a qualified function name (`clang::SemaObjC::BuildClassMessage`) takes three lines in the "last set" line, since the panel is about 230 px wide. It wraps only between `::` and does not clip.
- A trace without the symbol table was tested by jest only, not in a browser: no stored report on the server lacks the table, and the functest fixture for it is not served.
- Modelled calls (reason `other`) are in Other, as the spec says. Case 27 suggests naming them "Modelled calls" or counting a call's statement as a call result; the ticket 09 worker or the lead may want to decide.
- "Last set" is the first Path Step that shows the entry as it ends, by node order. For a printed path that jumps back in node order it still holds, since it takes the earliest step whose node reaches the change.
- The classification of a region value without a name by the dump's text (no `conj_$` or `derived_$`) is an approximation. It is wrong for memory that mentions a call's symbol only in a part Clang cannot name; the name of such memory would be Clang's to give.
- mypy in this venv reports 19 environment errors, unrelated to the ticket (above).
