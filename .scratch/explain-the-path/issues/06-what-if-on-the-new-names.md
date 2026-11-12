# 06: What-If on the new names

**What to build:** A report reader writes a What-If Constraint on a caller's variable or on an access path such as `gl->cellsize` or `this->Current`, and gets a Path Verdict as for a local variable.
This ticket closes slice 2 of `../spec.md`.

**Blocked by:** 04, 05

**Status:** resolved

- [x] The left side of a comparison accepts access paths made of identifiers, `.`, `->`, `*` and constant subscripts, matched as text against display names, not parsed as C.
- [x] A name resolves to any variable of any frame or any symbol display name visible at the anchor Path Step that has an SMT-LIB term.
- [x] A name that resolves to more than one symbol gives an Unknown verdict that names the candidates.
- [x] The suggestion list offers every constrainable name at the selected Path Step, and choosing a frame-qualified entry resolves an ambiguous name.
- [x] "Holds throughout the path" works on access paths.
- [x] Functional tests cover a caller's variable, an access path, an ambiguous name and a trace without the new keys.
- [x] Slice acceptance in a browser at 1400 and 900 pixels on the two demos and three LLVM reports from the triage study.
- [x] Table A4 of `../../colorful-day/research/triage-study.md` is measured again with the study's own scripts on a fresh LLVM run, and the result is recorded in Comments.
- [x] Plist size and analysis time on that run are reported.
- [x] The CodeChecker documentation page describes the new names and the ambiguity verdict.

## Comments

2026-11-12, ticket 06 worker.

Commits: `codechecker@4a5db1481..e92a2d384` (mypy fix `4a5db1481`, server `7c268620e`, fixture names and functional tests `3da85f3da`, web `cebb7da2e` and `64f180381`, docs `e92a2d384`); `llvm-project@4bf1528255ed` (`dev-loop.sh fixture` also writes `what_if_names.json`).
No Clang change, no Thrift change, no DB migration.

### What a name is now

- One spelling everywhere, the panel's `function::name`, with `(anonymous namespace)::` left out as the frame headings already did; the path condition's qualified names and the labels' "in `function`" now use the same spelling (`functionName` in `ConstraintTrace.js`, `function_name` in `what_if.py`).
- At a Path Step a name stands for: a variable of the step's own frame or of any calling frame, written alone or as `function::name`; else memory the symbol table names (a region value's `name`, a derived symbol's `region`) whose solver term the step declares. A variable hides memory of the same text, as the panel does.
- Grammar (lead note on access paths): identifiers joined by `.` and `->`, after any `*`, with subscripts that are an integer or a name themselves, and `::` qualifiers, matched as text. Named subscripts go beyond the spec's "constant subscripts", because Clang names `Op.Node->ValueList[Op.ResNo].V.SimpleTy` (study case 25) that way.
- Anchored: a name must stand for exactly one value at the step, else Unknown naming the candidates: variables by `function::name` ("`n` names 2 values at this Path Step: `middle::n` and `top::n`. Write the one you mean."), memory by what its labels say ("the one before the path changed it; the one after `this->parse(prec::LogicalOr)` may have changed it, line 3486; ..."), recursion with "called at line N".
- Holds throughout: every value of the name along the path; memory may have several values at one step (the value before and after a call), variables of several frames may not, which gives Unknown.

### Decisions

- Resolution lives in `what_if.py` alone (`_Path._names_at`, `_one_value`, `_every_value`, and `constrainable_names` for the list), lead note 2. The page cannot ask the server for names without an API change, so `ConstraintTrace.whatIfNames` reads the trace the same way, and agreement is a test, not care: the server unit test `test_what_if_names.py` writes what the server resolves at every step of every fixture plus the two hand-written unit traces into `web/tests/projects/constraint_trace/what_if_names.json` (only with `UPDATE_WHAT_IF_NAMES=1`, otherwise it compares), and jest `WhatIfNames.test.js` checks the page's list against that file for both anchored and throughout. A mutation of the JS throughout rule made jest fail on `caller_frames`. Rejected: an RPC for the names, which would spend the one API bump slice 3 needs, and a hand-kept rule list on each side.
- A derived symbol's access path counts as a name of its memory, so `this->Current` covers the value before and after `parse()`. Rejected: region values only, which would make anchored `this->Current` silently mean the value before the call and leave "this field is never null" (story 30) unable to cover the replaced values. The cost: anchored on memory a call replaced is Unknown at later steps, with throughout as the way out, which the reason says.
- The suggestion list offers every name the check can decide (symbol with a solver term, integer, address), one entry per value: a value with a plain name is not repeated under its function, and an ambiguous `n` is offered as `middle::n` and `top::n`. A typed word also matches a part after `::`, `->` or `.`, so `n` finds `top::n` and `Simple` finds the case 25 path. With "Holds throughout" ticked the list is the throughout list. The aria label is now "Names at this step".
- The placeholder keeps its old preference (an own variable holding a symbol, then an integer) and otherwise takes the shortest name, which keeps it inside a 900 px field; a placeholder too long still ends in an ellipsis.
- Lead note 5: a variable whose symbol is not in Known here but is in the accumulated path condition shows that range with the same `dropped` tag; one never constrained still reads "no known range" (`top::n` reads `2 dropped`).
- Lead note 7: the suggestion list is at least 320 px wide, grows to the left to stay in the window, wraps names at `.`, `->`, `::` and `[`, keeps values on one line and a multi-interval range whole per interval. The Checked together row, the verdict's expression and the reason's code spans wrap at the same separators (they used to break inside `->` at 900 px).
- Fixed on the way: the Unknown verdict read "at Step 10.`n` names" with no space (Vue dropped the space between two tags); a long "called at X86ISelLowering.cpp:21815" heading ran 6 px past the panel at 900 px; a pre-existing mypy error in `codechecker_common/compatibility/multiprocessing.py` (mypy does not narrow `sys.platform in [...]`).

### Verification

- Server unit 139 (20 new: 18 in `test_what_if.py`, 2 in `test_what_if_names.py`), functest 46 (5 new: caller's variable, ambiguous name, access path, throughout on an access path, trace without the new keys), report-converter unit 159, jest 117 in 6 suites (18 new), Colorful Day lit 11 passed and 1 unsupported (no Clang change; run for completeness), eslint clean, pycodestyle clean, pylint 10.00, mypy clean. No tracked file left modified by the test runs.
- Agreement beyond the fixtures: the JS list equals the server's on study cases 1, 25 and 7 and on study case 9's 1,837-step trace, every step anchored and the last three throughout, 0 differences in 1,923 comparisons (one-off script, not committed).
- Browser, server restarted after the server change, `/Users/efulop/colorful-day-env/screens/`, 1400 and 900 px, each with a `-verdict` companion; no element of the panel overflows at either width after the fixes, and the suggestion list stays inside the window (572 to 892 at 900 px):
  - `t06-caller-frames-1400/900.png` (demo report 292, Step 10 in `inner`): typing `n` offers `middle::n` 6 and `top::n` 2 dropped; `n == 6` gives the Unknown naming both, `top::n == 3` is Infeasible, dying at Step 1.
  - `t06-access-path-1400/900.png` (report 290, Step 5): `li` offers `line`, `line->cells[0].width`, `line->next`, `line->next->cells[1].flags`; `line->next->cells[1].flags == 0` is Infeasible, dying at Step 3.
  - `t06-two-path-1400/900.png` (report 291, Step 2): `b == 0` is Infeasible right there, as before.
  - `t06-tmux-1400/900.png` (grid.c:1073, report 325, Step 8, tmux analyzed again with the current Clang): `gd->` offers `gd->hsize`, `gd->linedata`, `gd->linedata[py].cellsize`, `gd->linedata[py].cellused`, `gd->sy`; `gd->linedata == null` is Infeasible, dying at the arrow after step 2.
  - `t06-llvm-case1/25/7-1400/900.png`, below.

### The three study reports (ticket 05's LLVM run, stored as `t06-llvm-case1`, `t06-llvm-case25`, and `t05-llvm-case7`)

- Case 1 (`TokenAnnotator.cpp:3452`, report 296, Step 8). The triager's question was whether `parse()` replaced `this->Current`, and the deciding fact that a `parse()` with a null `Current` leaves it null. `this->Current == null` holding throughout is Infeasible and dies at Step 3, the "Assuming field 'Current' is non-null" right after `this->parse(prec::LogicalOr)`. Anchored at Step 8 it is Unknown and names the three values (before, after each `parse()`). Settles it: the path needs `parse()` to turn a null `Current` non-null, which it cannot, so false positive, now by one check instead of reading dumps.
- Case 25 (`MachineValueType.h:325`, report 301, Step 7, inside `getVectorElementType`). `VT` is now a caller variable of `LowerTRUNCATE` at the last step. `VT != 0` (and the same on `Op.Node->ValueList[Op.ResNo].V.SimpleTy`) is Infeasible, dying at the arrow after step 2, the call at line 22004 with no event; in the study it was Unknown ("the last frame has no variables"). Settles it: the bug needs `VT` to be `INVALID_SIMPLE_VALUE_TYPE`, which a `TRUNCATE` node being lowered never has.
- Case 7 (`MemorySanitizer.cpp:1865`, report 285, Step 13), the caller-variable case. `DataShadow != 0`, a caller variable of `handleAVX512VectorGenericMaskedFP`, is Infeasible right there; in the study it was Unknown ("no tracked value"). Does not settle it: `DataShadow` holds the concrete 0, so the check restates the path, and the deciding fact, the compiled-out `assert(DataIndices.size() > 0)`, is about a loop count no name reaches.

### Table A4 again

Run: ticket 05's LLVM run (`/Users/efulop/colorful-day-env/t05/reports`, 3546 TUs, current Clang, no Clang change since), plists 638,798,617 bytes, largest 27,040,071, user time 23,704 s (figures in ticket 05's Comments; LLVM not run again). Script: `/Users/efulop/colorful-day-env/t06/a4.py`, which calls the study's own `measure.report()` unchanged for the study's columns and adds the new ones with the server's resolution; `a4agg.py` deduplicates by (hash, file, checker) as `aggregate.py` does. Output `llvm-a4.jsonl`, `tmux-a4.jsonl` beside them. tmux is the 3.5a run analyzed again for this ticket (`/Users/efulop/colorful-day-env/t06/runs/tmux`).

"Named by panel" is the study's rule plus a calling frame's variable at the last step; "display name" is an entry that is one symbol with a memory name; "name or label" is an entry the panel shows as a variable, a label or an expression of them rather than a raw dump; "What-If addressable now" is the study's definition with the server's own resolution, anchored or throughout, at any step.

| group | entries | named by panel, study (2026-11-12 study) | named by panel now | display name | name or label | What-If addressable, study rule (study) | What-If addressable now | reports with >= 1 entry neither named nor labelled |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| LLVM all | 38,644 (38,664) | 9.3% (9%) | 9.3% | 26.9% | 84.8% | 11.4% (11%) | 39.0% | 743 of 1225 (61%), study 1112 (91%) neither named nor reg |
| core.CallAndMessage | 11,460 | 15% (15%) | 15% | 30% | 79% | 17% (17%) | 40% | 303 |
| optin.cplusplus.UninitializedObject | 14,495 | 3% (3%) | 3% | 27% | 87% | 4% (4%) | 40% | 166 |
| NewDelete / Move | 4,644 | 4% (4%) | 4% | 12% | 95% | 8% (8%) | 22% | 38 |
| core.NullDereference | 861 | 21% (21%) | 21% | 36% | 85% | 26% (26%) | 52% | 28 |
| core.DivideZero | 641 | 18% (18%) | 18% | 35% | 85% | 26% (26%) | 52% | 28 |
| tmux all | 458 | 28% (28%) | 28% | 44% | 90% | 36% (36%) | 67% | 15 of 30 |

- Absolute LLVM counts: named 3,592 by the study rule, 3,600 now; display name 10,378; name or label 32,776; addressable 4,393 by the study rule, 15,059 now.
- Calling frames add only 8 named entries: their symbols are mostly the analyzed function's parameters, which an own-frame variable already held at an earlier step. The gain is in names of memory and in What-If, not in variable names.
- Reports with at least one What-If name at some step: LLVM 1220 of 1225, tmux 30 of 30. The study's A1 rule (a variable with a solver term or an integer) gives LLVM 1184 of 1225 and tmux 30 of 30 on this run, against tmux 29 of 30 in the study.

### Open points

- Anchored What-If on memory a call replaced is Unknown after the call; there is no spelling for "the value after `parse()`" alone, only throughout. A spelling for it would need a decision on syntax.
- Memory is told apart by name only: two functions' `this->Current` read as one name, and two frames of a recursive function as one `f::n` (the reason then gives call lines, but no spelling picks one).
- 9.3% of the run's stack frames (1,442 of 15,514, counted over every diagnostic) have a function name with template arguments, a lambda or an operator, which the grammar cannot take before `::`; their variables can be named alone, and the list leaves the qualified form out.
- Values the panel cannot name cannot be constrained: extents, metadata, fields of temporaries (case 18) and pointees of call results; `this->Current->Tok.Kind` is Clang's name for the field of `Current` after the first `parse()`, which reads like the current one.
- Pre-existing, seen in the screenshots and left: "Arrow after step 2" as a dead-step label (ticket 03), and at 900 px a long variable name such as `Precedence` pushes its value to the next line.
