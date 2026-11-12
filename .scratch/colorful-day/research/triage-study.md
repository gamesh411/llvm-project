# Triage study: what constraint data answers for people who evaluate reports

Date of every claim: 2026-11-12.
Measured with the trace readers at `codechecker@978ea7699` (`constraint_trace.py` and `what_if.py` are identical to `codechecker@b7b6d1c72`) and with `llvm-project@6dc2604108f7` checked out.
The LLVM data is `/Users/efulop/colorful-day-env/cfg2/reports-all-on`, the 3546-TU LLVM + Clang run of the CFG and store pass, analyzed by the Clang of `llvm-project@a2b47aba60aa..5370369696d0` and finished 2026-11-12 07:36.
The tmux data is `/Users/efulop/colorful-day-env/reports-tmux` (tmux 3.5a, trace format version 2, written 2026-11-12 09:13).
Scripts and raw output are in `/Users/efulop/colorful-day-env/triage-study/`: `measure.py`, `aggregate.py`, `last_step.py`, `assert_scan.py`, `select_sample.py`, `dump.py`, `whatif.py`, with per-report rows in `llvm.jsonl` and `tmux.jsonl`.
Plists were read directly through `ConstraintTrace`; no CodeChecker server was started or contacted.
What-If verdicts below come from running `what_if.check_what_if` offline on the plist's trace, the same code the server runs.

The LLVM run was built with `LLVM_ENABLE_ASSERTIONS=OFF`, so every TU has `-DNDEBUG` and the analyzer never saw an `assert`.
That shapes the false positive mix of this study, see the limits section.

## Population

The 3545 plists hold 7332 diagnostics, 3255 of them with a trace.
The 4077 without a trace are `deadcode.DeadStores` (4073) and `security.insecureAPI.rand` (4), which are not path-sensitive.
Reports from headers repeat across TUs, so the tables count unique reports by (report hash, file, checker), keeping the first: 1225 unique traced reports.
This is not CodeChecker's deduplication, which stored 3928 reports including dead stores.
tmux has 30 traced reports.

## A. Quantitative tables

"From the trace" means the number is read from trace data as Clang wrote it.
"Approximated" means it is my classification of trace strings or plist path text, with the rule stated.

### A1. Coverage (from the trace)

| group | reports | with SMT-LIB | >= 1 symbol variable with SMT term, any step | same, incl. integer variables | >= 1 symbol variable with SMT term at the last step | ... whose symbol is on the path condition | no variables at the last step |
| --- | --- | --- | --- | --- | --- | --- | --- |
| LLVM all | 1225 | 1225 | 1119 (91%) | 1184 (97%) | 562 (46%) | 487 (40%) | 395 (32%) |
| tmux all | 30 | 30 | 30 | 30 | 30 | 29 | 0 |

Per checker (LLVM, any step; the last three columns were measured over all reports only):

| group | reports | SMT-LIB | >= 1 symbol var | incl. integer | final path condition empty |
| --- | --- | --- | --- | --- | --- |
| core.CallAndMessage | 497 | 497 | 461 | 493 | 2 |
| optin.cplusplus.UninitializedObject | 247 | 247 | 225 | 231 | 1 |
| security.ArrayBound | 86 | 86 | 83 | 86 | 0 |
| NewDelete / NewDeleteLeaks / Move | 64 | 64 | 62 | 64 | 0 |
| optin.cplusplus.VirtualCall | 57 | 57 | 34 | 42 | 0 |
| uninitialized family | 56 | 56 | 54 | 54 | 0 |
| core.NullDereference | 44 | 44 | 43 | 44 | 0 |
| core.NonNullParamChecker | 44 | 44 | 42 | 44 | 0 |
| core.DivideZero | 37 | 37 | 35 | 37 | 0 |
| core.BitwiseShift | 32 | 32 | 31 | 31 | 0 |
| core.StackAddressEscape | 29 | 29 | 20 | 28 | 0 |
| unix.Malloc / cstring / Stream | 12 | 12 | 11 | 11 | 0 |
| core.NullPointerArithm | 10 | 10 | 9 | 10 | 0 |
| other (< 10 each) | 10 | 10 | 9 | 9 | 0 |

"What-If usable" follows the server's rule in `what_if.py`: a symbol variable with an SMT term, or an integer, at some step.
A variable is usable only at steps where it is live, and the What-If input defaults to the selected step.

### A2. Path shape, median / p90 / max (from the trace and plist path)

| group | path pieces | events | steps where the path condition changes | final path condition entries | distinct atoms on it | "Assuming" events | reports with a loop-back event |
| --- | --- | --- | --- | --- | --- | --- | --- |
| LLVM all | 37 / 90 / 2022 | 12 / 28 / 1100 | 7 / 18 / 363 | 14 / 51 / 1430 | 15 / 54 / 1430 | 3 / 12 / 363 | 76 |
| core.CallAndMessage | 37 / 94 / 2022 | 11 / 28 / 1100 | 7 / 18 / 363 | 15 / 43 / 657 | 16 / 47 / 592 | 4 / 12 / 363 | 21 |
| optin.cplusplus.UninitializedObject | 28 / 74 / 220 | 9 / 19 / 62 | 4 / 19 / 67 | 13 / 140 / 817 | 15 / 122 / 802 | 1 / 6 / 50 | 4 |
| security.ArrayBound | 38.5 / 84 / 138 | 13 / 26 / 41 | 7 / 19 / 32 | 12.5 / 59 / 88 | 13 / 59 / 88 | 4 / 12 / 22 | 16 |
| NewDelete / Move | 57 / 93 / 110 | 21 / 30 / 41 | 9 / 14 / 24 | 21.5 / 58 / 1430 | 21.5 / 56 / 1430 | 4 / 10 / 12 | 7 |
| uninitialized family | 41 / 107 / 166 | 14 / 34 / 51 | 7 / 19 / 23 | 13 / 63 / 90 | 14 / 67 / 91 | 3 / 14 / 22 | 3 |
| core.NullDereference | 41.5 / 97 / 154 | 13.5 / 29 / 48 | 8.5 / 20 / 31 | 14.5 / 39 / 65 | 15 / 48 / 68 | 6.5 / 16 / 24 | 5 |
| core.DivideZero | 65 / 118 / 243 | 24 / 47 / 72 | 8 / 14 / 70 | 14 / 33 / 97 | 12 / 34 / 99 | 3 / 7 / 57 | 3 |
| unix.Malloc / cstring / Stream | 67.5 / 149 / 176 | 21.5 / 38 / 44 | 14 / 33 / 41 | 25.5 / 44 / 93 | 19.5 / 45 / 88 | 7.5 / 32 / 35 | 6 |
| tmux all | 35 / 101 / 116 | 12.5 / 30 / 40 | 8.5 / 16 / 27 | 14 / 31 / 45 | 13.5 / 33 / 35 | 6.5 / 13 / 25 | 11 |

"Steps where the path condition changes" counts the first step naming each node whose `path_condition` delta is non-empty; that is exact for version 2, since `exploded_nodes` holds only nodes that steps name.
The final path condition is the snapshot of the last step's node.
Loop-back events are counted from plist event text starting with "Looping back" (approximated).
The other per-checker rows are in `/Users/efulop/colorful-day-env/triage-study/llvm-tables.md`.

### A3. Symbol kinds on the final path condition (approximated from dumps)

An entry is classified by its symbol dump: one whole `reg_$`, `conj_$`, `derived_$`, `meta_$` or `extent_$` atom, or `compound` for any expression of several atoms or an atom with arithmetic or casts.
Atoms are the top-level symbols inside an entry, counted once per report.

| group | entries | reg | conj | derived | meta | extent | compound |
| --- | --- | --- | --- | --- | --- | --- | --- |
| LLVM all | 38,664 | 21% | 37% | 18% | 0% | 6% | 18% |
| core.CallAndMessage | 11,460 | 31% | 33% | 10% | 0% | 7% | 18% |
| optin.cplusplus.UninitializedObject | 14,495 | 9% | 44% | 21% | 0% | 9% | 18% |
| NewDelete / Move | 4,644 | 11% | 40% | 37% | 0% | 1% | 10% |
| core.NullDereference | 861 | 43% | 23% | 11% | 0% | 4% | 19% |
| core.DivideZero | 641 | 34% | 22% | 19% | 0% | 4% | 22% |
| tmux all | 458 | 41% | 25% | 11% | 2% | 3% | 18% |

| atoms on the path condition | atoms | reg | conj | derived | meta | extent |
| --- | --- | --- | --- | --- | --- | --- |
| LLVM all | 38,590 | 26% | 47% | 21% | 0% | 7% |
| tmux all | 438 | 52% | 27% | 15% | 2% | 5% |

What the dump says about a `conj_$` symbol's origin, from the trace: its type, location context (`LC`), statement ID (`S`) and block visit count (`#`), as in `conj_$5{int, LC10235, S8579640, #1}`.
The trace has no statement text, source location or callee name for an `S` ID, and does not say whether the symbol is a call's return value, an invalidated region's new value or a loop-widened value.
Approximations from the dump: only 35 conj atoms across the LLVM run have a visit count above 1, so loop-iteration and widening symbols are rare on path conditions.
8046 derived atoms have a `conj_$` parent, which is nearly all of them (about 8100), so most `derived_$` symbols are fields of a region that a conjured value replaced, typically by invalidation or an opaque return.

### A4. Can a user name the symbols on the final path condition? (from the trace, rule approximated)

"Named by panel" applies the UI's `symbolNames` rule: some variable held exactly that symbol dump at a step up to the last.
"Unnamed reg" entries are a whole `reg_$` dump, whose text spells out the source access path (for example `reg_$5<... Element{SymRegion{reg_$3<const FormatToken * Token>},...}.MatchingParen>`), so a reader can decode them.
"What-If addressable" means the entry or one of its atoms is the value, or an atom of the value, of a symbol variable with an SMT term at some step, so a What-If term on that variable constrains it.

| group | entries | named by panel | unnamed reg | What-If addressable | reports with every entry named | reports with >= 1 entry neither named nor reg |
| --- | --- | --- | --- | --- | --- | --- |
| LLVM all | 38,664 | 9% | 16% | 11% | 11 | 1112 (91%) |
| core.CallAndMessage | 11,460 | 15% | 23% | 17% | 8 | 437 |
| optin.cplusplus.UninitializedObject | 14,495 | 3% | 8% | 4% | 1 | 232 |
| NewDelete / Move | 4,644 | 4% | 9% | 8% | 0 | 63 |
| core.NullDereference | 861 | 21% | 31% | 26% | 0 | 38 |
| core.DivideZero | 641 | 18% | 24% | 26% | 0 | 36 |
| tmux all | 458 | 28% | 22% | 36% | 2 | 24 |

So 75% of the LLVM path condition entries can only be referred to by a raw dump of a conjured, derived, extent or compound symbol.

### A5. Where the path condition is built, relative to the bug's frame (from the trace)

Each insert or replace in a node's `path_condition` delta is attributed to that node's `frame` in `stack_frames`, against the frame of the last step's node.

| group | changes | in the bug's frame | in a caller of the bug's frame | in a callee that returned before the bug | reports whose bug is not in the top frame | reports with > 1 frame |
| --- | --- | --- | --- | --- | --- | --- |
| LLVM all | 39,393 | 19% | 77% | 4% | 927 (76%) | 1008 |
| core.CallAndMessage | 11,638 | 38% | 55% | 7% | 299 | 342 |
| optin.cplusplus.UninitializedObject | 14,696 | 0% | 100% | 0% | 247 | 247 |
| NewDelete / Move | 4,663 | 8% | 85% | 8% | 56 | 62 |
| core.NullDereference | 886 | 34% | 58% | 8% | 34 | 36 |
| core.DivideZero | 667 | 42% | 54% | 4% | 25 | 35 |
| tmux all | 479 | 46% | 44% | 10% | 17 | 20 |

In LLVM, three quarters of bugs end inside an inlined callee, and most constraints come from the caller frames above it.
That is why 32% of LLVM reports have no variable at all at their last step (A1): the variables of the frames that built the path condition are not in scope there.

### A6. Other measures

| measure | LLVM | tmux | how |
| --- | --- | --- | --- |
| path condition changes at a step that is an "Assuming" event | 38% | 70% | from the trace, step kind from plist path |
| ... at another event (mostly "Calling constructor", "Calling 'f'", "Entering loop") | 33% | 9% | same |
| ... at a control edge only, with no event on that node | 28% | 22% | same |
| "Assuming" events whose step adds nothing to the path condition | 812 of 6426 (13%) | 4 of 217 | from the trace; the constraint may land on a neighbouring node, so approximated |
| final path condition entries whose range is `[1, UINT64_MAX]` (non-null pointer or non-zero 64-bit) | 40% | 36% | range string, approximated |
| ... whose range is exactly 0 | 35% | 31% | range string |
| ... another single value | 8% | 7% | range string |
| ... any other range | 17% | 25% | range string |
| reports whose Bug Path passes over an `assert(` line | 639 of 1225 (52%) | not measured | approximated: source lines between consecutive path locations in one file, at most 40 lines apart |
| median / max stack frames per trace | 3 / 186 | 2 / 8 | from the trace |
| variable values over all lifetimes: symbol / integer / address | 11,716 / 6,202 / 2,077 | - | from the trace |

The node kinds that carry path condition changes are PostStmt 5105, BlockEdge 3193, CallEnter 2296, and fewer than 140 each for the rest (from the trace).
Variables in the trace are named local variables and parameters only; a struct such as `NestedNameSpecifierLoc QualifierLoc` or a field such as `this->Current` never appears as a variable, so neither the panel nor What-If can refer to it by name.

## B. Qualitative pass: aggregate

30 reports, drawn by `select_sample.py` with seed 20261112 from the unique LLVM reports, stratified by checker group and by path length below or above the group's median (list in `/Users/efulop/colorful-day-env/triage-study/sample.tsv`).
Verdicts: 23 false positive, 5 true positive, 2 cannot tell.
Of the 5 true positives, one is an actionable leak (case 21), one is a benign uninitialized copy (case 9), and three are by design (cases 23, 24, 30).

### Triager questions, ranked by the number of cases that needed them

A case can need more than one question.

| rank | question I had to answer | cases | count | does today's trace answer it | does What-If answer it | addition that would (Clang side / UI side) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Where did this value come from: which call or statement produced this conjured symbol or concrete value | 1, 2, 4, 5, 9, 10, 11, 12, 14, 27 | 10 | partly in all 10: the dump tells conjured from initial values and gives type and statement ID, never the statement text, callee, or whether it is a return value or an invalidation | no: these values are almost never variables (A4: 11% addressable) | Clang: record, per conjured symbol, the statement text and location, the callee, and the reason (return value, invalidation by call X, widening); UI: label symbols with it |
| 2 | Does the analyzer know the correlation between these two facts (same call twice, container size and contents, `kind()` and `dyn_cast`, error flag and payload) | 2, 4, 8, 10, 11, 12, 13, 20 | 8 | no; in case 10 the two unrelated symbols are visible only if one reads the statement IDs | no: both sides are unnamed symbols, and the grammar relates a variable to a constant only | Clang: the origin data of row 1, plus whether each call was inlined and why not; UI: mark two symbols that came from the same call text |
| 3 | Can a real caller or input produce this: what does the path require of the entry inputs | 6, 9, 15, 16, 27, 28, 29 | 7 | yes in 6, 27, 29, where the deciding constraint is on a parameter of the top frame; no in the rest | confirms in 6 and 27 (one-term Infeasible), decisive in 29 only with two terms together | UI: list the path condition entries on top-frame parameters and globals as "this path requires"; server: a Z3 model of the path condition mapped to variable names, a concrete witness |
| 4 | Is there an assert or documented precondition on the path that the analyzer did not see | 3, 7, 14, 15, 25, 28 | 6 | no; the asserts are compiled out by `-DNDEBUG` | expressible in 3, 14, 15, 28 and Infeasible there, but the assert contradicts the bug condition directly, so the answer is known before checking; not expressible in 7 and 25 | not trace data: analyze with assertions on; a Clang note listing asserts compiled out on the path would need preprocessor data |
| 5 | Which assumption does the bug hinge on: why does it think p is null here | 3, 5, 18, 25, 27 | 5 | yes in 5, 18, 25, 27; in 18 and 25 the deciding constraint had no event in the Bug Path and no name, and only the raw path condition showed it | usable in 5 and 27, restating what the trace shows; not in 18 and 25 (`EB` and `VT` have no tracked value at the last step) | Clang: name field symbols by access path, such as `Builder.InsertPt.Block`; UI: mark steps where the path condition changed with no event |
| 6 | What non-constraint state does the analyzer hold: heap ownership, dynamic type, region contents | 8, 17, 19, 20 | 4 | no; these live in checker state, dynamic type info and the store, which the trace does not carry | no | Clang: per-node checker state (MallocChecker region state), dynamic type and cast assumptions, and store bindings of the regions the report names |
| 7 | Was this value invalidated or forgotten by that call | 1, 4, 22 | 3 | partly in 1 and 4 (a `derived_$` of a `conj_$` shows a replaced value, not by which call); no in 22 (a struct is not a variable) | no | Clang: invalidation events with the invalidating call; UI: a per-variable value history with the reason for each change |
| 8 | How many loop iterations or what sizes did it assume | 16, 19, 26 | 3 | partly: loop events count iterations, `extent_$` entries are raw | no: sizes and extents are not variables | Clang: name extents and index expressions; server: the concrete witness of row 3 |
| 9 | Is the reported condition a problem at all, by design | 23, 24, 30 | 3 | not a reasoning question; the trace is irrelevant | no | none on constraint data |

Case 21 needed none of these: reading the code showed the missing `free`.

What-If outcomes across the 30 cases:
- In 3 cases (6, 27, 29) a What-If check on the deciding question could be typed and returned Infeasible; only in case 29 did it tell me something I had not already read off the path condition, and only with the two-term `m < 4096 && n < 4096` (`m < 4096` alone is Feasible).
- In 9 cases (1, 2, 3, 4, 5, 14, 15, 16, 28) a check could be typed and returned Infeasible, but it negated the condition the bug event already states, such as `Start != 0` for "Passing null pointer value via 1st parameter 'Start'".
- In 18 cases the deciding fact was about an unnamed symbol, a non-constraint state, an assert, or a design question, so no What-If term could express it.
- The Baseline Verdict was Feasible in every check I ran (17 checks over 16 cases).

## B. The 30 case notes

Each note gives the verdict, then (a) the deciding fact, (b) the question about the analyzer's reasoning, (c) whether the trace and What-If answered it, with the check typed and its result as `order` of the first dead step, and (d) what missing data would have answered it faster.
Path length is the number of plist path pieces.

1. `core.NullDereference`, `clang/lib/Format/TokenAnnotator.cpp:3452`, 22 pieces, short.
   False positive.
   (a) `Start` is null only when `Current` was null, and `parse(prec::LogicalOr)` leaves a null `Current` null, so the later `Current` non-null assumptions cannot follow.
   (b) Was `this->Current` invalidated by the `parse()` call?
   (c) Partly: the path condition shows `Current` as `derived_$9{conj_$5{int, LC10235, S8579640, #1}, ...}`, a replaced value, without naming the call; What-If cannot name the field, and `Start != 0` is Infeasible at order 18, which restates the event.
   (d) The invalidating call's text and whether `parse` was inlined.
2. `core.NullDereference`, `clang/lib/Format/WhitespaceManager.h:343`, 33 pieces, short.
   False positive, likely.
   (a) `CellCounts[0] >= 2` means `Cells` is not empty, yet `Cells.begin()` was assumed null at line 1358.
   (b) Where did `CellIter`'s symbol come from, and does it know cell counts and cells are related?
   (c) Partly: the panel names `CellIter` as `conj_$99` with `[0, 0]`; `CellIter != 0` holding throughout is Infeasible at order 14, which restates the "Loop body executed 0 times" event.
   (d) That `conj_$99` is the result of an uninlined `begin()`.
3. `core.NullDereference`, `clang/lib/Format/FormatToken.cpp:231`, 51 pieces, long.
   False positive.
   (a) A comma token inside a braced list always has a `Next`, and `assert(ItemBegin)` at line 229 says so, but it is compiled out.
   (b) Is there an assert on this path the analyzer did not see?
   (c) The event "Assuming field 'Next' is null" already shows the assumption; `ItemBegin != 0` holding throughout is Infeasible at order 40, which only encodes the assert by hand.
   (d) Nothing in the trace; an assertion-enabled build.
4. `core.NullDereference`, `llvm/lib/Support/DeltaTree.cpp:243`, 79 pieces, long.
   False positive.
   (a) The node `DoSplit` creates from a full leaf is a leaf, but the analyzer took the interior-node branch on it because its leaf flag and count are `derived_$313{conj_$287{...}}`, values it no longer knows.
   (b) Where did this symbol come from, and was the new node's state forgotten?
   (c) Partly: the dump shows a field of a conjured heap region, not which call conjured it; `InsertRes != 0` is Infeasible at order 59, a restatement of "Passing null pointer value via 3rd parameter".
   (d) Conjured symbol origin (the allocation and constructor at `DoSplit`).
5. `core.CallAndMessage`, `llvm/lib/Transforms/Scalar/SROA.cpp:1992`, 31 pieces, short.
   False positive.
   (a) Successors of a block ending in a conditional branch are never null; the null came from comparing the successor with another opaque value.
   (b) Why does it think `SuccBB` can be null?
   (c) Yes: the panel names `SuccBB` as `conj_$121` with `[0, 0]` at line 1987; `SuccBB != 0` is Infeasible at order 11, which restates the event.
   (d) That `conj_$121` is the dereference of an uninlined `successors()` iterator.
6. `core.CallAndMessage`, `clang/lib/Sema/SemaExprObjC.cpp:2772`, 27 pieces, short.
   False positive.
   (a) The bug needs `SuperLoc.ID == 0`, an invalid location, together with a null `ReceiverTypeInfo`, which the documented contract of `BuildClassMessage` excludes; `ActOnSuperMessage` gets the location of the `super` keyword.
   (b) What does this path require of the entry function's inputs?
   (c) Yes, and it was decisive: no event mentions `SuperLoc`, but the path condition names `SuperLoc` with `[0, 0]`; `SuperLoc != 0` is Infeasible at order 24, which confirms it is the only hinge.
   (d) A "this path requires" list of top-frame input constraints would have shown it in one line.
7. `core.CallAndMessage`, `llvm/lib/Transforms/Instrumentation/MemorySanitizer.cpp:1865`, 33 pieces, short.
   False positive.
   (a) `assert(DataIndices.size() > 0)` at line 5195 rules out the empty loop at 5238 that leaves `DataShadow` null; it is compiled out.
   (b) Is there an assert on this path the analyzer did not see?
   (c) No: there are no variables at the last step, and `DataShadow != 0` there is Unknown ("has no tracked value at this Path Step").
   (d) An assertion-enabled build.
8. `core.CallAndMessage`, `llvm/tools/llvm-ar/llvm-ar.cpp:1124`, 48 pieces, long.
   False positive.
   (a) `kind() == K_AIXBIG` is exactly `BigArchive::classof`, so the `dyn_cast` cannot fail after that test.
   (b) Does it know that `kind()` and the dynamic type are correlated?
   (c) No: the cast assumption "Assuming 'OldArchive' is not a 'CastReturnType'" is dynamic type state, not a constraint, so it is absent from the trace; What-If cannot express it.
   (d) Dynamic type and cast assumptions in the snapshot.
9. `core.CallAndMessage`, `llvm/include/llvm/Support/YAMLTraits.h:753`, 2022 pieces, long.
   True positive, benign: in input mode, with a `Kind` string matching none of 180 cases, `enumFallback` copies the uninitialized `Kind` before `yamlize` overwrites it.
   (a) `Kind` is declared without an initializer in `MappingTraits<LeafRecord>::mapping` and only set when outputting.
   (b) Is there a concrete input that drives this path?
   (c) The final path condition has 363 entries, nearly all unnamed `conj_$...{_Bool, ...}` results of `matchEnumScalar`; it did not help, and `Val != 0` is Feasible because `Val` is an address.
   (d) Grouping of repeated constraints from one call site, with the callee's name.
10. `core.uninitialized.UndefReturn`, `llvm/include/llvm/ADT/APSInt.h:78`, 33 pieces, short.
    False positive.
    (a) `DestTy->isRealFloatingType()` returns the same value both times it is called in `handleScalarCast`, so the path with it false at line 3894 and true at 3904 is impossible.
    (b) Does it know two calls of the same function on the same argument agree?
    (c) Partly: two `conj_$...{_Bool, LC185289, S...}` symbols with different statement IDs are on the path condition, unnamed; no variable to type.
    (d) Statement text of each conjured symbol.
11. `core.uninitialized.Assign`, `llvm/include/llvm/Support/Error.h:535`, 20 pieces, short.
    False positive.
    (a) `CounterStack.push({C})` just ran, so `CounterStack.empty()` is false and the loop sets `LastPoppedValue`.
    (b) Does it know the stack is not empty after a push?
    (c) No: three unnamed entries, no variables at the last step.
    (d) Origin of the `empty()` result and that `std::stack` contents are not modeled.
12. `core.UndefinedBinaryOperatorResult`, `llvm/lib/Support/VirtualFileSystem.cpp:1991`, 141 pieces, long.
    False positive.
    (a) `checkMissingKeys` returning true at line 1987 means the required `type` key was seen, which set `Kind`.
    (b) Does it know that relation, and was `checkMissingKeys` inlined?
    (c) No: "Assuming the condition is false" is the only trace of it, and `Kind` is uninitialized, not a symbol.
    (d) Origin of the conjured return value and the reason the call was not inlined.
13. `core.uninitialized.Branch`, `llvm/lib/Bitcode/Reader/BitcodeReader.cpp:196`, 50 pieces, long.
    False positive.
    (a) `moveInto` returns `takeError()` without writing `Entry` only when there is an error, and then `if (Error E = ...)` returns.
    (b) Does it know the error flag and the returned `Error` agree?
    (c) No: the relevant values are fields of temporaries, unnamed.
    (d) Field symbols named by access path.
14. `core.DivideZero`, `llvm/lib/Target/X86/X86TargetTransformInfo.cpp:5992`, 57 pieces, short.
    False positive.
    (a) `assert(CurrOpSizeBytes > 0 && CurrNumEltPerOp > 0)` at line 5973 holds for legal types; compiled out.
    (b) Where did the concrete 0 in `CurrOpSizeBytes` come from?
    (c) Partly: the panel shows `CurrOpSizeBytes = 0` as a concrete value, not why; `CurrOpSizeBytes != 0` is Infeasible at order 45, a restatement.
    (d) Provenance of concrete values (which expression produced the 0).
15. `core.DivideZero`, `llvm/lib/IR/AutoUpgrade.cpp:6006`, 42 pieces, short.
    False positive.
    (a) `UpgradeIntrinsicFunction` only upgrades names matching `^create[234]`, so `StringSwitch` never reaches `.Default(0)`; `assert(N > 1)` says so too.
    (b) Is there an invariant from another function or an assert the analyzer did not see?
    (c) No: the string tests are unnamed `_Bool` symbols; `N > 1` is Infeasible at order 33, restating that `N` is 0.
    (d) Nothing in the trace; the invariant lives in another function.
16. `core.DivideZero`, `llvm/lib/Target/X86/X86TargetTransformInfo.cpp:5510`, 76 pieces, long.
    False positive.
    (a) For every legal vector `MVT` wider than 128 bits, elements are at most 128 bits wide, so `NumElts >= NumSubVecs` and `SubNumElts` is never 0.
    (b) Is there any concrete type that gives `SubNumElts == 0`?
    (c) Partly: `SubNumElts` is a quotient of conjured symbols; `SubNumElts != 0` is Infeasible at order 73, which restates the event.
    (d) A concrete model of the path condition (for example `SizeInBits = 256, NumElts = 1`) would have made the impossibility visible at once.
17. `cplusplus.NewDeleteLeaks`, `clang/include/clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h:352`, 56 pieces, short.
    False positive.
    (a) The memory allocated by libc++ `std::function`'s `__clone` is owned by the new `std::function`, which its destructor frees.
    (b) Where does it think the pointer was lost?
    (c) No: the leak is heap ownership state, not constraints.
    (d) MallocChecker's state for the symbol and what still referenced it.
18. `cplusplus.NewDeleteLeaks`, `llvm/lib/Transforms/Vectorize/VPlanLowering.cpp:198`, 37 pieces, short.
    False positive.
    (a) The new recipe leaks only if the builder's insertion point has no block, but it was set to `EB`'s terminator at line 185, whose parent is `EB`.
    (b) Why does it think the recipe was not inserted?
    (c) Yes, but only in the raw path condition: `derived_$345{conj_$340{...},temp_object{const VPInsertPoint, S16873379}.Block}` is `[0, 0]`, with no event for it; `EB != 0` at the last step is Unknown ("has no tracked value").
    (d) A name for the field symbol and a mark on the step where it was assumed.
19. `cplusplus.NewDelete`, `llvm/lib/Support/APInt.cpp:1915`, 110 pieces, long.
    False positive.
    (a) The move assignment at `APInt.h:642` frees the old buffer and then copies the new one into `U` with `memcpy`, so `Tmp` points to live memory; and after `Tmp` became 0 the loop at line 2319 ends.
    (b) What does the analyzer think `Tmp.U.pVal` holds after the move, and why did the loop run again?
    (c) No: region contents are store state, not constraints.
    (d) Store bindings of the regions the report names.
20. `cplusplus.NewDelete`, `llvm/lib/Support/APFloat.cpp:5209`, 65 pieces, long.
    False positive.
    (a) The elements of a `DoubleAPFloat` have IEEE double semantics (asserted at line 4812), so destroying the temporary copy runs the IEEE destructor, not `~DoubleAPFloat`.
    (b) Does it know the semantics pointer of the copied element?
    (c) No: the semantics comparisons are unnamed symbols.
    (d) Field symbols named by access path, and conjured symbol origins.
21. `unix.Malloc`, `clang/tools/c-index-test/c-index-test.c:2999`, 39 pieces, short.
    True positive: `Locations` leaks when `parse_file_line_column` fails.
    (a) The early `return errorCode` skips `free(Locations)`.
    (b) None about the analyzer's reasoning.
    (c) Not needed.
    (d) Nothing.
22. `unix.cstring.NullArg`, `clang/include/clang/AST/NestedNameSpecifierBase.h:309`, 86 pieces, long.
    False positive, likely.
    (a) `QualifierLoc` tested false at line 2534 and is not reassigned before it is tested true at line 2583.
    (b) Was its value replaced by one of the calls in between?
    (c) No: `QualifierLoc` is a struct, so it is not among the variables, and its fields are unnamed.
    (d) A value history for struct fields with the reason for each change.
23. `optin.cplusplus.UninitializedObject`, `clang/tools/libclang/CXIndexDataConsumer.h:117`, 25 pieces, short.
    True positive by the checker's definition, by design: the C-API structs are filled in by the caller after construction.
    (a) The 25 fields are set by `handleObjCImplementation` after the constructor.
    (b) Is the uninitialized state ever read?
    (c) Not a constraint question.
    (d) Nothing.
24. `optin.cplusplus.UninitializedObject`, `llvm/include/llvm/Bitstream/BitCodes.h:56`, 30 pieces, long.
    True positive by definition, by design: `Enc` is only read when `IsLiteral` is false.
    (a) The literal constructor leaves `Enc` unset deliberately.
    (b) Is `Enc` read for literals?
    (c) Not a constraint question.
    (d) Nothing.
25. `security.ArrayBound`, `llvm/include/llvm/CodeGenTypes/MachineValueType.h:325`, 28 pieces, short.
    False positive.
    (a) A `TRUNCATE` node being lowered has a valid simple value type, but the path needs `VT` to be `INVALID_SIMPLE_VALUE_TYPE` (0); the assert at line 318 is compiled out.
    (b) Why does it think `SimpleTy` is 0?
    (c) Yes in the path condition (`VT` with `[0, 0]`, appearing at the call at line 22004 with no event); `VT != 0` at the last step is Unknown because the last frame has no variables.
    (d) A mark on the step where it was assumed, and What-If on a caller frame's variables.
26. `security.ArrayBound`, `llvm/lib/CodeGen/RegAllocPBQP.cpp:506`, 60 pieces, long.
    Cannot tell, leaning false positive.
    (a) The matrix is `(Allowed1.size() + 1) x (Allowed2.size() + 1)` by construction and by the asserts at lines 499-500, but I could not tie the heap extent the analyzer used to the loop bounds it assumed.
    (b) How many iterations and what extent did it assume?
    (c) Partly: the loop events show the iterations, the extent is a raw `extent_$` entry; sizes are not variables, so What-If cannot state them.
    (d) Named extents and index expressions, and a concrete model.
27. `core.NonNullParamChecker`, `clang/lib/Sema/CheckExprLifetime.cpp:1450`, 17 pieces, short.
    False positive.
    (a) `getEntityLifetime` never returns `LK_Assignment` for an initialization, and the assert at line 1136 says so; the path needs `LK == 7`.
    (b) Which single value does the bug hinge on, and can any caller produce it?
    (c) Yes: the path condition has two entries, the panel names `LK` as `(conj_$11{intptr_t, ...}) & 7U` with `[7, 7]`; `LK != 7` is Infeasible at order 12, which confirms it.
    (d) That `conj_$11` is the `PointerIntPair` returned by `getEntityLifetime`.
28. `core.NonNullParamChecker`, `clang/lib/AST/ExprConstant.cpp:7312`, 74 pieces, long.
    Cannot tell.
    (a) `assert(ObjectArg)` at line 7305 claims a trivial copy or move assignment always has an object argument, but I could not rule out the path through line 9205 with `This` null.
    (b) Can a real call reach this with no object argument?
    (c) No: `ObjectArg != 0` is Infeasible at order 63, which restates the bug.
    (d) A concrete witness, or an assertion-enabled run.
29. `core.BitwiseShift`, `llvm/lib/Support/APInt.cpp:1363`, 32 pieces, short.
    False positive.
    (a) The path needs `v[n-1] == 0` and `m + n == 0` in 32-bit arithmetic, so `m + n` must wrap; callers pass word counts with a non-zero top divisor word.
    (b) What does the path require of `m`, `n` and `v`?
    (c) Yes, in the path condition as an unnamed compound entry `(reg_$5<unsigned int m>) + (reg_$6<unsigned int n>)` in `[0, 0]`; `m < 4096 && n < 4096` is Infeasible at order 25, while `m < 4096` alone is Feasible.
    (d) A concrete model, which would read `m = 4294967295, n = 1`.
30. `optin.cplusplus.VirtualCall`, `clang/lib/Basic/Targets/LoongArch.h:142`, 18 pieces, short.
    True positive by definition, harmless: no subclass of `LoongArch32TargetInfo` overrides `setABI`.
    (a) The class hierarchy.
    (b) Does any subclass override the method?
    (c) Not a constraint question.
    (d) Nothing.

## Limits of this study

- The LLVM run had assertions off, so asserts that would have pruned paths were invisible; 52% of reports pass over an `assert(` line by my approximate scan, and 6 of the 30 cases turned on one. With assertions on, the false positive mix and the share of question 4 would change.
- One person triaged 30 reports in one sitting, with no second reviewer; the verdicts on cases 2, 22, 26 and 28 are the least certain.
- The sample is LLVM and Clang only, which is C++ heavy, with deep inlining and many uninlined accessor calls; tmux, the only C project measured, differs sharply (A1, A4, A5), and I did not triage tmux reports.
- Checker groups with few reports (unix.Malloc family 12, Move 5) are represented by one or two cases.
- The symbol kind, naming and range classes are my classification of dump strings, not data the trace carries as fields.
- "Assuming events without a path condition change" may count constraints that landed on a neighbouring node.
- What-If verdicts were computed offline with the server's own module, not through the web UI, so UI-side limits (which variables the input offers at the selected step) were judged from the trace, not observed.
- I timed nothing, so "faster" in the case notes is my judgement of which data would have shortened the reading, not a measurement.
