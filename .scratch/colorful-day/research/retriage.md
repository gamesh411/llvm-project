# Retriage: the 30 study cases with the finished constraint panel

Date of every claim: 2026-11-13.
Measured at `llvm-project@297dab849243` and `codechecker@fe046668e`, against the dev server on port 8002.
The study this repeats is `triage-study.md` in this directory, dated 2026-11-12, at `llvm-project@6dc2604108f7` and `codechecker@978ea7699`.
Scripts, the page's reader modules they run, per-case panel dumps and traces are in `/Users/efulop/colorful-day-env/retriage/`.
Screenshots are `/Users/efulop/colorful-day-env/screens/rt-*.png`, each with the panel's text beside it as `rt-*.txt`.

## Method

### Reports

Each case was matched by file, line, checker and bug hash (`issue_hash_content_of_line_in_context`) from the study's plist (`cfg2/reports-all-on`) to the plist of the same name in `/Users/efulop/colorful-day-env/t05/reports`, the full NDEBUG LLVM run made with the Clang that writes everything the trace has now (`match.py`, `match.tsv`).
All 30 cases are still there, each matching exactly one diagnostic, at the same diagnostic index, with the same number of path pieces and trace steps as in the study.
No case disappeared and no path changed.

Eight cases were already stored and were used from their runs: 1 (`t06-llvm-case1`), 6, 19, 27 and 29 (`t08-llvm`), 7 (`t05-llvm-case7`), 9 (`t09-llvm-case9`) and 25 (`t06-llvm-case25`).
The other 22 were stored from 20 copied t05 plists as run `retriage`.
The stored traces of the reused runs were compared with the t05 plists (`samecheck.py`, `digits.py`): apart from what store rewrites (file paths to file IDs, `path_index` to kind and index), they differ only in symbol and location-context numbers in cases 6, 19 and 27, which were analyzed again for ticket 08 by the same Clang.
Report IDs are in `ids.tsv`.

The web bundle served by the package was built at 00:46 from a working tree whose `.build-commit` stamp reads `cfdb0827b`, the last committed vue-cli change at that time.
It contains the ticket 09 strings ("Show an example", the comparison reading), and no vue-cli source changed after it apart from commit metadata, so the page tested is that of `codechecker@fe046668e`.

### Reading the panel

Every case was read as a triager would, with the study's deciding question in hand, from the last Path Step's This step view, the Whole path list and, where a name could carry it, What-If.
For all 30 cases the panel text was produced by the page's own modules, `ConstraintTrace.js` and `SnapshotRows.js` copied from `codechecker@fe046668e`, run in Node by `panel.mjs`, which repeats `Report.vue`'s labelling and the panel's range wording (`dumps/<case>.txt`).
13 cases were also opened in Chrome with `chrome-devtools-axi` (`shot.sh`): 1, 3, 4, 6, 7, 9, 10, 11, 12, 16, 18, 20 and 25, which include every case scored as newly answered.
Where the Node text and the page differed, the page was taken: the page names some control steps "Step N" where `panel.mjs` printed "Edge before Step N", which changes no score.
What-If checks went through the Thrift API (`whatif.py`, `whatif.out`) and, for 1, 6, 7, 16, 20 and 25, also through the page.
Examples came from `checkWhatIf(..., withExample=true)` (`example.py`) and, for 9 and 16, from the page.

### Scales

The study's scales are kept.
For the deciding question: **yes** when the panel shows the fact the triager needed without reading the analyzer's source or a raw dump, **partly** when it shows part of it or only through a hover or a raw dump, **no** otherwise, and **n/a** when the question is not about the analyzer's reasoning.
For What-If the study's three buckets: **A** the deciding question could be typed, **B** a check could be typed but it only negates or restates what the bug event or the panel already says, **C** nothing about the deciding question could be typed.
**Decisive** means the verdict told the triager something not already readable in the panel, as the study meant it for case 29.
"Before" is the study's own score, from its case notes, with its question table where the notes say nothing about a question.

## Per-case table

Report IDs are on the dev server; R is run `retriage`.
"Feature" names what answered or helped: origin label, access-path name, same-call tag, caller group, silent marker ("assumed with no event"), Whole path list, example, What-If.

| # | report | verdict | deciding question (category) | before | after | feature | What-If: typed, verdict, bucket | still missing |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 296 | FP | Was `this->Current` replaced by `parse()`? (origin, invalidated) | partly | yes | Whole path: entry `this->Current` null, replaced value "`this->Current` after `this->parse(prec::LogicalOr)` may have changed it, line 3486" non-null | `this->Current == null` throughout, Infeasible at Step 3, A, not decisive | whether `parse` was inlined, and why not |
| 2 | 549 R | FP likely | Where did `CellIter` come from; are cell counts and cells related? (origin, correlation) | partly | partly | origin label "result of `begin()`, line 1367", same-call tag "another `Cells.begin()` result" | `CellIter != null` throughout, Infeasible, B | the relation between `CellCounts` and `Cells`; `CellCounts[0]` reads as a raw `reg_$106<...conj_$105...>` |
| 3 | 568 R | FP | Is there an assert the analyzer did not see? (assert, assumption) | no | no | event "Assuming field 'HasUnescapedNewline' is 0"; outside the panel, the macro-expansion note shows `assert(ItemBegin)` at line 229 as `((void )0)` | `ItemBegin != null` throughout, Infeasible, B; `Token->Next != null` throughout is Feasible because the null `Next` is of `ItemEnd`, raw | the null value is a raw `reg_$86<...conj_$71...>.Next` (memory behind a call result); asserts are compiled out |
| 4 | 436 R | FP | Where did the new node's leaf flag come from; was it forgotten? (origin, correlation, invalidated) | partly | partly | origin labels: `IN` "result of `operator new()`, line 317 in DoSplit"; "a value after `NewNode->RecomputeFullDeltaLocally()` may have changed it, line 328" | `InsertRes != null` is Unknown: three frames name it and two have the same spelling `DeltaTreeNode::DoInsertion::InsertRes`; C | names for fields behind a call's result ("a value" is `IsLeaf` or `NumValuesUsed`); unique names for recursive frames |
| 5 | 402 R | FP | Why is `SuccBB` null? (assumption, origin) | yes | yes | origin label "result of `operator*()`, line 1986" on `SuccBB`, Call results group | `SuccBB != null`, Infeasible, B | nothing for the question |
| 6 | 356 | FP | What does the path require of the entry inputs? (caller) | yes | yes | Whole path: first row of Entry inputs `SuperLoc` = `SuperLoc.ID` 0 | `SuperLoc.ID != 0`, Infeasible at Step 7, A, not decisive | nothing for the question |
| 7 | 285 | FP | Is there an assert the analyzer did not see? (assert) | no | no | caller group of `handleAVX512VectorGenericMaskedFP` shows `DataShadow` 0 at the last step; outside the panel, the macro-expansion note shows `assert(DataIndices.size() > 0)` at line 5196 | `DataShadow != null`, Infeasible at Step 13 ("dies right there"), B | the assert is compiled out |
| 8 | 569 R | FP | Does it know `kind()` and the dynamic type agree? (correlation, state) | no | partly | access-path name and replaced-value label: `ArchiveOrError.TStorage.__ptr_->Format` 6 beside `BigArc` 0 | `BigArc != null`, Infeasible, B | dynamic type and cast state; enum values read as numbers (6, not `K_AIXBIG`) |
| 9 | 378 | TP benign | Is there a concrete input that drives this path? (caller, origin) | no | yes | Whole path Call results: `outputting()` 0 and every `matchEnumScalar()` 0, same-call tag "+178"; example all 0 | none for the input, C | grouping of 363 rows from one call site; the enum string of each call is only in the hover |
| 10 | 554 R | FP | Does it know two calls of `isRealFloatingType()` agree? (correlation, origin) | partly | yes | same-call tags: "result of `isRealFloatingType()`" 0 at line 3894 and 1 at line 3904, each "another `DestTy->isRealFloatingType()` result" | none, C (a call result is not a name, no comparison of two names) | nothing for the question |
| 11 | 463 R | FP | Does it know the stack is not empty after a push? (correlation, origin) | no | yes | Call results: "result of `empty()`, stack:237 in `std::stack<StackElem>::empty`" 1 | none, C | nothing for the question |
| 12 | 493 R | FP | Does it know `checkMissingKeys` implies `Kind` was set; was it inlined? (correlation, origin) | no | yes | Call results: "result of `checkMissingKeys()`, line 1987" 1, an uninlined call | none, C | why the call was not inlined; the key-status `Seen` flag is a raw dump |
| 13 | 544 R | FP | Do the error flag and the returned `Error` agree? (correlation) | no | partly | labels "`E.Payload` of the value from `Error E = Stream.advance().moveInto(Ent…`, line 193" null and "a value after `Stream.advance()` may have changed it, line 193" 1 | none, C | names for fields of temporaries ("a value") |
| 14 | 444 R | FP | Where did the 0 in `CurrOpSizeBytes` come from? (origin, assert) | partly | partly | Replaced values "a value after `LT.second.getSizeInBits()` may have changed it, line 5952" 0, with a link to the step | `CurrOpSizeBytes > 0`, Infeasible, B | provenance of a concrete value; the deciding assert at 5973 is compiled out |
| 15 | 476 R | FP | Is there an invariant from another function or an assert? (caller, assert) | no | partly | Call results: three `starts_with()` results at 5984, 5988, 5997 and three in `StringSwitch` | `N > 1`, Infeasible, B | call-result labels drop the string argument (only in the hover); the `StringSwitch` prefixes are a parameter `S`; the invariant lives in another function |
| 16 | 442 R | FP | Is there any concrete type that gives `SubNumElts == 0`? (sizes, caller) | partly | yes | example with What-If bounds: under `SizeInBits <= 2048 && NumElts <= 1024` at Step 14 the example reads `SizeInBits` 1153 and 8 elements, not a legal vector type (and the macro-expansion note shows the compiled-out `assert((SizeInBits % 128) == 0)` beside it) | `SubNumElts != 0`, Infeasible, B; the bounds are Feasible and served the example | comparing two names (`NumElts * 128 >= SizeInBits` cannot be typed); the `NumElts` row is named `SubNumElts` |
| 17 | 550 R | FP | Where does it think the pointer was lost? (state) | no | no | none | none, C | MallocChecker state |
| 18 | 564 R | FP | Why does it think the recipe was not inserted? (assumption) | yes (raw) | partly | Replaced values row null, "last set at Step 5", labelled "a value after `*this` may have changed it, ilist_node.h:123 in ...getIterator" | none, C (`EB` is not a name at the last step) | a name for the field of a temporary: the raw dump said `temp_object{const VPInsertPoint}.Block`, the label hides it in the hover |
| 19 | 371 | FP | What does it think `Tmp.U.pVal` holds after the move? (state, sizes) | no | no | none | none, C | store bindings |
| 20 | 525 R | FP | Does it know the semantics of the copied element? (correlation, state) | no | yes | access-path names in Entry inputs: `(this->Floats[1].U.IEEE.semantics->precision + 64) / 64` at least 2 and `(this->Floats->U.IEEE.semantics->precision + 64) / 64` at most 1, "assumed with no event" in the constructor | `this->Floats[1].U.IEEE.semantics->precision == 53` throughout, Infeasible at Edge after Step 3, A, not decisive | which destructor the copy runs (store and dynamic type) |
| 21 | 449 R | TP | none | n/a | n/a | not needed | n/a | nothing |
| 22 | 386 R | FP likely | Was `QualifierLoc` replaced by a call in between? (invalidated) | no | no | none: `QualifierLoc` and its fields appear nowhere | none, C | names for a struct local copied from a call result |
| 23 | 426 R | TP by design | Is the uninitialized state read? (design) | n/a | n/a | not a constraint question | n/a | nothing |
| 24 | 575 R | TP by design | Is `Enc` read for literals? (design) | n/a | n/a | not a constraint question | n/a | nothing |
| 25 | 301 | FP | Why is `SimpleTy` 0? (assumption, assert) | yes (raw) | yes | Whole path first row `DstVT` = `Op.Node->ValueList[Op.ResNo].V.SimpleTy` 0, "assumed with no event at Edge after Step 2"; caller groups name `VT` 0; outside the panel the macro-expansion note shows the assert at line 318 | `VT != 0`, Infeasible at Edge after Step 2, B (the index is `SimpleTy - 1`, so this negates "negative index -1") | the assert is compiled out |
| 26 | 383 R | cannot tell | How many iterations and what extent did it assume? (sizes) | partly | partly | silent markers on the loop; example gives extents 5 and 6 | none, C | names for extents and fields behind call results (`AllowedRegs`, `NumOpts` stay raw) |
| 27 | 374 | FP | Which value does the bug hinge on; can a caller produce it? (assumption, caller, origin) | yes | yes | Whole path: `LK` = "value from `std::memcpy(&R, this->Data, sizeof (R))` & 7" 7 under Other | `LK != 7`, Infeasible, A, not decisive | that the value is `getEntityLifetime()`'s result (checker-modelled `memcpy`) |
| 28 | 558 R | cannot tell | Can a real call reach this with no object argument? (caller, assert) | no | no | Call results show `isCopyAssignmentOperator()` 1 and `isExplicitObjectMemberFunction()` 0, which narrows the call | `ObjectArg != null`, Infeasible, B | provenance of the concrete null `This`; 29 raw rows under Other |
| 29 | 370 | FP | What does the path require of `m`, `n` and `v`? (caller) | yes | yes | Whole path entry input `m + n` 0; example `n` 1, `m + n` 0 | `m < 4096 && n < 4096`, Infeasible at order 25, A, decisive; `m < 4096` alone Feasible | a value for `m` in the example |
| 30 | 458 R | TP harmless | Does a subclass override the method? (design) | n/a | n/a | not a constraint question | n/a | nothing |

## Aggregates

### Deciding question, per case

| score | before | after | cases after |
| --- | --- | --- | --- |
| yes | 6 | 12 | 1, 5, 6, 9, 10, 11, 12, 16, 20, 25, 27, 29 |
| partly | 7 | 8 | 2, 4, 8, 13, 14, 15, 18, 26 |
| no | 13 | 6 | 3, 7, 17, 19, 22, 28 |
| n/a | 4 | 4 | 21, 23, 24, 30 |

Newly answered (no or partly before, yes after): 1, 9, 10, 11, 12, 16, 20, seven cases.
One case went the other way in readability: 18 was "yes, in the raw path condition" in the study and is partly now, because its label hides the field name the dump showed.

### Per question category

A case can count under more than one category, as in the study.

| category | cases | before yes / partly / no | after yes / partly / no | answered or helped by |
| --- | --- | --- | --- | --- |
| Value origin | 1, 2, 4, 5, 9, 10, 11, 12, 14, 27 | 0 / 10 / 0 | 7 / 3 / 0 | origin labels (all 10), same-call tags (2, 9, 10), Call results group (5, 9, 11, 12) |
| Correlation | 2, 4, 8, 10, 11, 12, 13, 20 | 0 / 1 / 7 | 4 / 4 / 0 | same-call tag (10), call-result labels that show an uninlined call (11, 12), access-path names (20) |
| Real caller or input | 6, 9, 15, 16, 27, 28, 29 | 3 / 0 / 4 | 5 / 1 / 1 | Whole path list (6, 9, 27, 29), example (16, 29) |
| Unseen assert | 3, 7, 14, 15, 25, 28 | 0 / 0 / 6 | 0 / 0 / 6 | nothing in the panel; see the note below |
| Which assumption | 3, 5, 18, 25, 27 | 5 / 0 / 0 | 4 / 1 / 0 | Whole path rows with "assumed with no event" (25), access-path names (25), origin labels (5, 27) |
| Non-constraint state | 8, 17, 19, 20 | 0 / 0 / 4 | 0 / 2 / 2 | access-path names show the constraints next to the state (8, 20) |
| Invalidated or forgotten | 1, 4, 22 | 0 / 2 / 1 | 1 / 1 / 1 | replaced-value labels (1, 4) |
| Iterations or sizes | 16, 19, 26 | 0 / 2 / 1 | 1 / 1 / 1 | example (16, 26) |
| By design | 23, 24, 30 | n/a | n/a | none needed |

The study's question table scores value origin "partly in all 10", while its notes for cases 11 and 12 say "No"; the table's score is used here.
The study's question table scores "which assumption" as yes in 5, 18, 25 and 27 and leaves 3 out; case 3's note says the event already shows the assumption, so it is counted yes before and after.

Unseen asserts are not something the constraint panel can show, but the report page already does in three of the six cases.
CodeChecker's macro-expansion notes, an existing feature that both the study's and this run's plists carry, show `assert(...)` on a Bug Path line as "Macro Expansion `((void )0)`": the deciding assert is visible in case 3 (line 229), 7 (line 5196) and 25 (line 318), and not in 14, 15 and 28.
The study read plists offline and did not look at the page, so its "no" for this category undercounts what the page showed already on 2026-11-12.
The assertions-on rerun (`asserts-on-rerun.md`) removes all six of these cases, which is the real answer to this category.

### What-If

| bucket | study, 2026-11-12 | retriage | cases now |
| --- | --- | --- | --- |
| A: the deciding question could be typed | 3 | 5 | 1, 6, 20, 27, 29 |
| of which decisive | 1 | 1 | 29 |
| B: typed, only negates or restates | 9 | 10 | 2, 3, 5, 7, 8, 14, 15, 16, 25, 28 |
| C: nothing about the deciding question could be typed | 18 | 15 | 4, 9, 10, 11, 12, 13, 17, 18, 19, 21, 22, 23, 24, 26, 30 |

New in A: case 1, through "Holds throughout" on `this->Current`, and case 20, through access-path names of the semantics fields.
Neither is decisive, because the Whole path list already shows the row the check contradicts, as with 6 and 27 in the study.
New in B: 7, 8 and 25, where caller-frame variables made a name available at the last step; each check negates the bug event.
Case 16 used What-If bounds (`SizeInBits <= 2048 && NumElts <= 1024` at Step 14, Feasible) to get a readable example, which is what answered it.
Its invariant, `NumElts * 128 >= SizeInBits`, needs a comparison of two names, so the case counts under B for the `SubNumElts != 0` check it could type.
Case 4's check is Unknown because two recursive frames have the same spelling, which the docs list as a limit.
The baseline was Feasible in all 24 checks (20 in `whatif.out` and 4 bound checks on case 16).
The example, new since the study, helped in 16 and 29, repeated single values in 6, 9 and 25, and gave no value for symbols that are not rows (case 29's `m`).

## What is still missing, ranked by cases it blocks

1. **Names for memory behind a call's result, a temporary, or a struct copied from a call result**: 2, 3, 4, 13, 18, 22, 26 (7 cases).
   The panel says "a value after X may have changed it" or shows the raw dump, and in 18 the label is less informative than the dump it replaces.
2. **Compiled-out asserts**: 3, 7, 14, 15, 25, 28 (6 cases).
   Not trace data; the macro-expansion notes show three of them, and an assertions-on run removes all six.
3. **Relations between two values**: 2, 4, 8, 13, and 16 for What-If (5 cases).
   The same-call tag covers equal call text only; container size and contents, error flag and payload, kind and cast are not related anywhere, and What-If cannot compare two names.
4. **Non-constraint state** (dynamic type and cast assumptions, heap ownership, store bindings): 8, 17, 19, 20 (4 cases).
5. **Provenance of concrete values**: 14, 15, 28 (3 cases).
   A variable holding a concrete 0 or null does not say which expression produced it.
6. **Naming that misleads**: 4 (recursive frames share one spelling), 7, 10, 28 (`this` of another object read as the analyzed function's `this`), 16 (a value named by the variable later reassigned), 27 (a checker-modelled `memcpy` instead of `getEntityLifetime()`) (6 cases, none fully blocked, all slowed).
7. **Call-result labels without arguments**: 9, 15 (2 cases).
   The string argument that decides the case is only in the hover.
8. **Volume**: 9 (363 rows from one call site), 28 (77 rows, 29 of them raw), 6, 22, 28 (identical `__min_element()` rows) (4 cases slowed).

## Defects seen

None was fixed.

| id | kind | report | screenshot | what |
| --- | --- | --- | --- | --- |
| D1 | product | 285 (case 7); also 554 (case 10), 558 (case 28) | `rt-case7-requires-1400.png` | `this` of a callee's object (`reg_$102<const class llvm::Use * this>`) is named `this`, so `Mask` and `WriteThru` both read `this->Val` with different values and Entry inputs list `this` three times, all read as the analyzed function's `this`. |
| D2 | product | 436 (case 4) | `rt-case4-requires-1400.png` | Recursive frames: three Whole path rows are named `DeltaTreeNode::DoInsertion::e` with values 0, 0 and 15, and What-If cannot pick one (`InsertRes` is Unknown, two of its frames have the same spelling). |
| D3 | product | 564 (case 18) | `rt-case18-requires-1400.png` (the red outline is mine) | A derived symbol of a temporary's field loses the field: `derived_$345{conj_$340{...},temp_object{const VPInsertPoint}.Block}` reads "a value after `*this` may have changed it, ilist_node.h:123 in ...getIterator", and `.Block` is only in the hover. |
| D4 | product | 442 (case 16) | `rt-case16-subnumelts-1400.png` | The result of `getVectorMinNumElements()` (the code's `NumElts`) is named `SubNumElts` in Whole path and in This step, because `SubNumElts` was initialized from it, so two rows named `SubNumElts` read "not 0" and 0. |
| D5 | product | 378 (case 9), 458 (case 30), 564 (case 18) | `rt-case18-requires-1400.png` | Invalidation by a constructor prints its argument as the statement: "`Key.Data` after `"Kind"` may have changed it", "a value after `Triple` may have changed it", "after `*this`". The `*this` form was left open after ticket 04; the literal and argument forms are new examples. |
| D6 | product, minor | 356 (case 6); also 386, 558 | `rt-case6-min-element-1400.png` | Five call-result rows read identically, "result of `__min_element()`, min_element.h:47, another `__min_element(…)` result +3", with no step to tell them apart. |
| D7 | visual | 285 (case 7, line 1865), 301 (case 25, line 325) | `rt-case7-requires-1400.png`, `rt-case25-requires-1400.png` | At 1400 pixels with the panel open, the last event's bubble in the source runs under the panel and its text is cut. |
| D8 | visual, predates Colorful Day | 568 (case 3, line 229) | `rt-case3-requires-1400.png` | The same "Macro Expansion `((void )0)`" note is shown twice for one line, and its "Macro Expansion" label is light grey on grey. |

## Against the tickets' claims

Cases looked at during the tickets were checked afresh.

- Case 1 (tickets 02, 04, 06): the label and access path read as claimed.
  Ticket 06 says `this->Current == null` throughout "settles the case"; it is Infeasible at Step 3 as claimed, but with the Whole path list on screen the verdict is foreseeable, so it is counted as expressible and not decisive.
- Case 2 (ticket 03): agreed, the origin is answered and the relation between cell counts and cells is not.
- Case 6 (ticket 08): agreed, `SuperLoc` 0 is the first row of Entry inputs.
- Case 7 (tickets 05, 06): agreed that the caller group shows `DataShadow` 0 and that the What-If only restates the path; the same Whole path also shows defect D1.
- Case 10 (ticket 03): agreed.
- Case 18 (ticket 04): agreed that it is not answered; in addition the label now hides the `.Block` field the raw dump spelled out (D3), which the study had read off the dump.
- Case 25 (tickets 04, 06): the name is as claimed.
  Ticket 06 says `VT != 0` "settles the case"; the array index is `SimpleTy - 1`, so the check is the negation of the bug event "negative index -1", which the study's scale puts under B and not decisive.
- Case 27 (tickets 03, 08): agreed, partly on origin and under Other.
- Case 29 (tickets 08, 09): agreed, including the `Val` row of an inlined callee under Entry inputs and the example `n` 1 with `m + n` 0.
- The study itself: its "no" for unseen asserts misses the macro-expansion notes in cases 3, 7 and 25 (see the note under the category table).

## Limitations

- The same person read the study first and knows every verdict and deciding fact, so "answered" was judged by someone who already knew what to look for; a triager meeting these reports cold may need more than the panel shows, and the newly-answered count is an upper bound.
- One project, LLVM and Clang, analyzed with assertions off; the C project tmux, where the study found What-If's reach highest, was not retriaged.
- 30 cases, one triager, no second reviewer; cases 2, 22, 26 and 28 keep the study's least certain verdicts.
- 17 of the 30 cases were read through the page's reader modules in Node and the API, not in the browser; those modules are the page's own, but the Vue rendering (clamping, hover-only text) was seen for 13 cases only.
- Time to answer was not measured, as in the study.
