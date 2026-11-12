# 05: Caller-frame variables

**What to build:** At every Path Step the panel shows the variables of the calling functions as well as the current one, grouped by function, so it is no longer empty inside an inlined callee.

**Blocked by:** 01

**Status:** resolved

- [x] Clang writes the variables of every frame above the node's own in a new snapshot list, with the frame as part of each entry, encoded as deltas like the other lists.
- [x] The existing `variables` list keeps its shape and meaning, and the trace stays at version 2.
- [x] With emission off the plist output is byte-identical to before. Symbol renumbering with emission on is accepted and noted in Comments.
- [x] Lit covers a Path Step inside an inlined callee two calls deep, with a variable of the same name in two frames.
- [x] Both readers expose the caller variables through their reader class, with tests.
- [x] The Variables section is one group per stack frame, each headed by its function and call site, the current frame first and expanded, callers collapsed when there are more than a few.
- [x] Verified in a browser on the several-contexts demo and on an LLVM report with no variable at its last Path Step today.
- [x] Plist size on the LLVM run is reported, including the trace with the most stack frames.

## Comments

2026-11-12, ticket 05 worker.

Commits: `llvm-project@3c0cd591fc73` (Clang and lit), `4bc2c540fea2` (Clang docs), `a03b594a35d1` (trace format doc, `demo/caller-frames.c`, dev loop); `codechecker@f664a3467..da6f46c19` (Python reader `f664a3467`, fixtures and functest `7d2f1c5b7`, web `bbd3f31f7`, docs `da6f46c19`).

### What Clang writes

- A new node list `caller_variables`, entries `[frame, name, value, kind]` or `[frame, name, value, kind, smt, signed]`, `frame` an index into `stack_frames`, sorted innermost caller first, then by name. `variables` is unchanged.
- Deltas match entries by their first two values (frame and name), since several frames have an `n`; `diffTraceLists` takes a key width per list, and the assertion that each delta rebuilds its list covers the new list (the build has assertions on, and the whole LLVM run passed).
- Each frame is read the way the own frame was: direct bindings of that frame, the top frame's parameters by their initial value until first written, and the globals the function names. Bindings are collected once per node for all frames, and the globals a function names are cached per function instead of re-walking its body for every snapshot.
- Caller variables' symbols get symbol table and `expressions` entries, SMT terms, and SMT-LIB declarations in `smt_declarations`, so ticket 06 can resolve `(variable, frame, symbol)` and parse a caller's term with the node's declarations without a Clang change.

### Decisions

- A global is the same memory in every frame, so only the innermost frame whose function names it lists it; an outer frame leaves it out (a local of the same name that shadows it does not count as showing it). Rejected: listing it under every frame, which repeats a row and costs bytes per frame.
- A frame with no variable to show is not written. The analyzer drops a caller's locals at the call unless the caller reads them afterwards, so most caller groups on real code are the analyzed function's parameters; this is the analyzer's liveness, not a filter of ours (captured in Open Brain).
- Symbol renumbering with emission on is accepted: reading a caller's top-frame parameters and globals creates their region-value symbols earlier.
- UI grouping (lead note 1): one group per frame from `snapshotRows`, which builds every group's rows with the same `variableRows` helper as the own frame, so labels, readable ranges, the clamped-label tooltip and the `new`/`narrowed` tags are the same code. Row keys are `frame N variable n` for callers, so three `n` are three rows. Without callers the section looks exactly as before (no heading), which keeps old traces and top-frame steps unchanged.
- Headings: function name (with `(anonymous namespace)::` dropped for display, full name in the title) and "called at line N", a link to the step nearest the call in the parent frame. The own frame is first, always open, aligned with the callers' names; callers collapse with a chevron button (`aria-expanded`), start closed when there are more than three (`EXPANDED_CALLERS`), and a reader's choice is kept per frame across steps. A closed group shows its variable count.
- Symbols held by a caller variable are not "Other symbols".
- Names inside expressions and on path condition rows (lead note 2): `symbolNames(order)` now names a symbol by a variable of the step's own frame that holds it, else by the innermost caller that holds it, else by the step frames' history as ticket 04 did. A name that comes from another frame than the step's is written `function::name` (gdb's form) when a variable of that name in some shown frame holds something else at that step; with no clash it stays plain, so existing displays do not change. Two frames holding one symbol under one name (`m` passed down) is no clash. A path condition row named `top::n` shows the dump under it instead of the label `n`. Rejected: always qualifying names from other frames, which would change ticket 04's output on every callee-derived name.
- Picker: sameSnapshot now compares caller lists too, and the picker adds callers' differing variables (as `function::name`) only when the line's own variables leave two rows alike, so `several-contexts.c` line 5 still reads `flag = not 0` / `flag = 0`.
- Reader interface for ticket 06: Python `snapshot()`, `lifetimes('caller_variables')`, `entry()` (with `frame`) and `frame(index)`; JS `snapshot().caller_variables` and `frame(index)`. What-If is untouched.

### Verification

- Emission off byte-identical (apart from the revision string): 22 of 22 small inputs and 146 of 146 tmux TUs, two runs per binary. Emission on: all 22 and 146 equal outside the caller list once IDs are normalized (steps' ranges, own variables and path condition equal; declarations and table entries a superset), `/Users/efulop/colorful-day-env/t05/` (`compare.py`, `small.txt`, `tmux.txt`).
- Lit: new `constraint-snapshots-callers.c` (inside `inner` two calls deep, `n` in three frames, own list unchanged, deltas inserted once per call and untouched while the callee runs, table entries, SMT terms behind `%if z3`, off has no key). Colorful Day subset 10 passed, 1 unsupported; `clang/test/Analysis` 1272 discovered, 1252 passed, 14 unsupported, 5 expectedly failed, 1 failed (the user's untracked `bstring-UninitRead-partial-init.c`); `clang-extdef-mapping` rebuilt with Clang. `dev-loop.sh lit` now also lists the names and callers tests.
- CodeChecker: report-converter unit 159 (2 new), server unit 119, functest 41 (1 new, fixture `caller_frames`), jest 99 in 5 suites (7 new); eslint clean; pycodestyle clean, pylint 10.00, mypy clean; clang-format clean on the diff. No tracked file left modified.
- Browser, `/Users/efulop/colorful-day-env/screens/`, 1400 and 900 px; no panel element overflows and no frame heading is wider than the panel at either width:
  - `t05-caller-frames-1400/900.png` (report 267, step 10 in `inner`): `inner` called at line 17 with `h`; `middle` called at line 23 with `g`, `k` 7, `m` at least 6, `n` 6; `top` with `m`, `n`. `t05-caller-frames-collapsed-900.png`: closing `middle` leaves "4 variables" and the What-If section stays at y = 764 before and after. `t05-caller-frames-tags-1400.png` (step 5): `m` tagged `new` in both `middle` and `top`, and the path condition row reads `top::n` 2, dropped.
  - `t05-several-contexts-1400/900.png` (report 266): inside `take`, `several_contexts` shows `a`, `b`, `p`; `t05-picker-1400.png`: line 5 still reads `flag = not 0` and `flag = 0`.
  - `t05-llvm-case7-1400/900.png` (study case 7, `MemorySanitizer.cpp:1865`, report 285, step 13), a report with no variable at its last step: `getCleanShadow` has none ("No variable of this function is known here"), and `handleAVX512VectorGenericMaskedFP` shows `DataShadow` 0, `Mask`, `WriteThru` non-null, `MaskIndex`, `WriteThruIndex` and `I` with no known range. On the triage question ("is there an assert on this path the analyzer did not see?"): partly. The panel now shows that the null is the caller's `DataShadow`, still 0, which points at the loop that should have set it; the compiled-out assert at line 5195 that rules that out cannot show in any snapshot. `DataShadow` becomes a name What-If can use once ticket 06 lands.

### LLVM run (3546 TUs, NDEBUG database of the first run, `-j8`, emission on, `/Users/efulop/colorful-day-env/t05/reports`, `measure.py`, `result.json`)

| Measure | Ticket 05 | Ticket 03 (slice 1) |
|---|---|---|
| Plists | 3545, 638,798,617 bytes (+1.85%) | 627,216,851 |
| Largest | 27,040,071 `CompilerInvocation.cpp` (+0.9%) | 26,800,385 |
| User | 23,704 s (+1.6%) | 23,339 s |
| Wall | 3144 s | 6478 s (shared machine) |
| Max RSS | 3.95 GB | 4.03 GB |

- All 3546 TUs analyzed, none failed, with assertions on.
- The caller list is 767,714 bytes of JSON plus 4,387 bytes of strings only it names: 0.96% of trace JSON without CFG bodies, 0.33% with them. The plist grew 11.6 MB, more than the list's JSON, because XML costs several times JSON per integer and the callers' symbols add table entries and SMT-LIB declarations.
- 44,123 of 67,641 nodes have a caller list, 27,950 caller entries written as inserts or replacements, 83,049 frame groups shown over all nodes.
- The trace with the most stack frames is study case 9 (`YAMLTraits.h:753`, `CodeViewYAMLTypes.cpp`): 186 frames, but at most 6 deep at once, 914 nodes; its caller list is 17,451 of 475,534 trace JSON bytes (3.7%). The deepest stacks are 16 frames (`User.h:167`), with caller lists of 233 to 527 bytes. The spec's size risk did not materialize: lists change only at calls and returns, and callers' dead locals are not in the store.
- User time is comparable only roughly: a stuck system `ReportCrash` process used a core throughout, and three web builds and one functest ran during the first half.

### Open points

- A caller's dead locals are gone at the call, so the groups are often only the analyzed function's parameters; values that were live only before the call stay in the path condition and the name history.
- A top-frame parameter whose range the analyzer dropped reads "no known range" in its group although the path condition still has it (as for the own frame).
- `function::name` is a display form; whether What-If accepts it as the frame-qualified syntax is ticket 06's decision.
- At 900 px a 33-character identifier in a heading breaks inside the word, since it alone is wider than the panel.
- The tree's labels still clip at 900 px (pre-existing).

