# Defect fixes after the retriage

Date of every claim: 2026-11-13.
Fixes defects D1, D3, D4, D5, D6 and D7 of `retriage.md` in this directory; D2 (recursive frames) and D8 (macro-expansion note) were left alone, as asked.
Measured at `llvm-project@42bc8045ea7e` and `codechecker@65086ae9d`, against the dev server on port 8002.
Scripts, the re-analyzed reports, panel text and comparisons are in `/Users/efulop/colorful-day-env/df/`.
Screenshots are `/Users/efulop/colorful-day-env/screens/df-*.png`, each with the panel's text beside it as `df-*.txt`.

The principle applied to every fix: a wrong name is worse than no name, and a name must never make two different values look like the same thing, or one thing look like another.

## Reports

The ten TUs of study cases 1, 6, 7, 9, 10, 16, 18, 22, 25, 28, 29 and 30 were analyzed again with the new Clang (NDEBUG database of the LLVM run, `-j8`, Z3 refutation, emission on, 198 s wall), together with tmux `grid.c`, and stored as run `defects` (`analyze-store.sh`, `cdb.json`, `cdb-tmux-grid.json`).
Every case kept its Bug Path length and event count.
Report IDs in `defects`: case 1 791, 6 802, 7 826, 9 782, 10 832, 16 807, 18 786, 22 795, 25 843, 28 836, 29 776, 30 759, tmux `grid.c:1073` 755 (`ids.tsv`).
The panel text of each was also produced by the page's own reader modules in Node (`node/panel.mjs`, `node/new-<case>.txt`).

## D1: `this` of another object read as the analyzed function's `this`

Cause, in Clang: `describeRegion` in `BugReporter.cpp` named every `CXXThisRegion` `this` and every variable by its name, whatever stack frame it belonged to.
The analyzer makes a region value of an inlined callee's `this` or parameter when it lost the object's address or the argument, as in case 7, where `Use *op_begin()` is `reinterpret_cast<Use *>(this) - NumUserOperands` and each `getArgOperand()` inlines `Use::get()` on an unknown `this`.
So `reg_$102<const Use * this>` and `reg_$127<const Use * this>`, two calls' values, both read `this`, and `Mask` and `WriteThru` both read `this->Val`.
The UI only showed what Clang wrote.
Telling the frame by `function::this` would not have told these two apart, since both are frames of `Use::get()`; that is the D2 question, so the fix gives no name.

Fix: a region value whose memory is a variable or `this` of a frame other than the analyzed function's (the top frame), or is reached from one through pointers that are initial or replaced values of memory, has no `name` and has a new key `in_call` (`llvm-project@a4ee24d9a656`).
`describeValue` refuses to name a pointer or index through such a value, so extents, derived regions and invalidated memory reached through it are unnamed too.
A derived symbol or an invalidation that names a callee's own local directly, such as `Tok` in "`Tok` after `lex(&Tok)`", keeps its name, because its label names the function it was made in.
The reader puts an `in_call` region value under Other instead of Entry inputs and shows its dump (`codechecker@31a544473`).

After (`df-d1-d7-case7-after-1400.png`, `df-d1-case7-other-after-1400.png`, 900 px versions beside them): Entry inputs of case 7 are `this` and `I->VTy` only, and under Other `Mask` reads `reg_$129<...reg_$127<const class llvm::Use * this>...>` and `WriteThru` `reg_$104<...reg_$102<...this>...>`, two values that no longer look alike.
Case 10 lists its three callee `this` values as three distinct dumps under Other (`node/new-10.txt`), case 28 likewise.
Case 29's `Val`, a parameter of the inlined `countl_zero`, moved from Entry inputs to Other as `reg_$25<unsigned int Val>`, which the ticket 08 acceptance had flagged.

## D3: a derived value of a temporary's field lost the field

Cause, in Clang: `describeRegion` gives the whole access path or nothing, and a temporary has no description, so `derived_$345{conj_$340{...},temp_object{const VPInsertPoint}.Block}` had no `region` and the UI fell back to "a value after ...".

Fix: a derived symbol whose `region` is absent gets `member`, the end of its access path after the nearest memory that has no description, such as `.Block` or `->next`, following pointers that are fields of such memory (`llvm-project@4597033ce5db`).
The reader labels it "`.Block` of a value after `X` may have changed it", "`->next` of the result of `head()`", or "`.f` of part of `a` after ..." when the replaced memory has a name (`codechecker@31a544473`).

After (`df-d3-d5-case18-after-1400.png`, `-900.png`): case 18's deciding row reads "`.Block` of a value after `ilist_iterator(*this)` may have changed it, ilist_node.h:123", null.
Other cases gain fields where they read "a value" before, such as case 16's "`.Quantity` of a value after `LT.second.getSizeInBits()`" and case 6's "`->ObjCMethodDeclBits.IsInstance` of a value after `Method->getClassInterface()`".

## D4: a value named by a variable that only held a copy of it

Cause, in the UI: `symbolNameLog` gave a symbol the name of the variable that held it, and of several variables of one frame that held it at one step, the last by name won.
In case 16, `unsigned NumElts = ...getVectorNumElements(); unsigned SubNumElts = NumElts;` puts the call's result in both before the next Path Step, so `SubNumElts` won; after `SubNumElts = NumElts / NumSubVecs` the result kept that name from the history, and two rows read `SubNumElts`, one "not 0" and one 0.
Ticket 04's rule "a region value inside an expression goes by the variable that held it first" was right in its wording; the log implemented "last".
The same mechanism named a region value by a callee's copy: case 16's `SrcTy` row was `Val`, and tmux's `xx` stood for the parameter `px` it was copied from.

Fix (`codechecker@2f4610231`): a variable names only the value it was last seen to hold, so a value it held before it was assigned another, or held only as a copy, takes an earlier variable's name that still names it, or none.
A copy does not take a name from a variable that still holds the value, all variables that start holding a value at one step are kept as candidates, and the value a variable started with goes by that variable when the step shows it, or shows neither.
Two names from other frames that would read alike are written `function::name`.
The rule for region values inside expressions is kept: with these names a variable now names one value, and a variable's name, unlike a memory name, can be frame-qualified.

After (`df-d4-case16-after-1400.png`, `-900.png`): the call result's row reads `NumElts`, the quotient's row `SubNumElts`.
In the tmux report the comparisons read `px >= end` and `px < (px + nx)` instead of `xx >= end` and `xx < (xx + nx)`, since the analyzer's constraint is on the parameter `px`, which `xx` only copied (`df-reg-tmux-1400.png`).

## D5: a constructor's invalidation printed its argument as the statement

Cause, in Clang: `printStatement` printed a `CXXConstructExpr` with `printPretty`, which prints an implicit construction as its arguments alone (`*this`, `"Kind"`, `Triple`).

Fix: a `CXXConstructExpr` that is not a `CXXTemporaryObjectExpr` prints as its class name and its arguments, without default arguments, in braces for list initialization (`llvm-project@5766148dc184`).

After: case 18 reads "after `ilist_iterator(*this)`", case 7 "after `ilist_iterator_w_bits(*this)`", case 9 "`Key.Data` after `StringRef("Kind")`" (`node/new-9.txt`), and case 30 "`->BitIntMaxAlign.__engaged_` of a value after `TargetInfo(Triple)`" (`df-d5-case30-after-1400.png`, `-900.png`).

## D6: identical call-result rows

Cause, in the UI: five results of `__min_element()` in a pruned `std::__min_element` frame have the same statement, location and function, and the same-call tag named only "another `__min_element(…)` result, no step +3".
Their first appearance in the trace does not tell them apart either: three show first at the same node and two at another, and both map to "Edge after Step 1".

Fix (`codechecker@b1988c688`): values whose labels read the same, from the same place in the same function, are counted in the order the analyzer made them, read from the symbol's number in its dump, and the label adds "2nd of 5" with a tooltip that says the analyzer does not assume they are equal.
The same-call tag leaves those values out and keeps others with the same call text elsewhere.
This applies to replaced values too, such as case 18's four `try_emplace` results.

After (`df-d6-case6-after-1400.png`, `-900.png`): "result of `__min_element()`, min_element.h:47, 1st of 5" to "5th of 5".

## D7: the last bubble ran under the panel

Cause, in the UI, older than Colorful Day: a step bubble is a CodeMirror line widget indented to its event's column and up to 640 px wide, so with the panel open beside the source it ran past the visible source.
It also inherits `white-space: pre` from the editor, so its documentation line never wrapped.
At 900 px the cut was worse than at 1400 px (`df-case7-before-900.png`, `df-case25-before-900.png`).

Fix (`codechecker@17aafbf18`): the bubble's width is at most the visible source width (`100cqw` of the editor column, which is a size container) minus the gutter, which `Report.vue` measures; its indent shrinks so that about 260 px stay for the text; and its documentation line wraps.

After: `df-d1-d7-case7-after-1400.png`, `-900.png`, `df-d7-case25-after-1400.png`, `-900.png`: every bubble ends at the source's edge and its text is whole.

## Regression checks

- tmux `grid.c:1073` (755, `df-reg-tmux-1400.png`, `-900.png`): nine entry inputs and eleven rows as at ticket 08, apart from `px` for `xx` above; no panel element overflows.
- Case 1 (791): `this->Current` null as an entry input and "`this->Current` after `this->parse(prec::LogicalOr)` may have changed it, line 3486" non-null, as before.
- Case 25 (843): `DstVT` reads `Op.Node->ValueList[Op.ResNo].V.SimpleTy` 0, assumed with no event at Edge after Step 2, as before.
- Case 29 (776): `n` not 0, `v` non-null and `m + n` 0 under Entry inputs, as before; `Val` moved to Other (D1).

## Checks

- Emission off: byte-identical to ticket 05's Clang (no Clang change since) on 22 of 22 small inputs and 146 of 146 tmux TUs, apart from the version string (`compare.py`, `small.txt`, `tmux.txt`).
  Emission on: every snapshot list equal after normalizing symbol and context numbers; the symbol tables differ only in `member` on 2 small and 5 tmux derived entries; C has no callee `this` and no implicit constructions, so no `in_call` appears there.
  The trace stays version 2; `in_call` and `member` are new optional keys.
- Colorful Day lit: 11 passed, 1 unsupported; `clang/test/Analysis`: 1272 discovered, 1252 passed, 14 unsupported, 5 expectedly failed, 1 failed (the user's untracked `bstring-UninitRead-partial-init.c`, as at every ticket); `diagnostics/` 42 passed after the last Clang change; `clang-extdef-mapping` rebuilt with Clang; clang-format clean on the diff.
  The new lit checks failed on the old binary (the `in_call` check first; the old output was `"B"` and no `member`).
- jest 147 in 8 suites (10 new), eslint clean; all 10 new tests fail against the `ConstraintTrace.js` of `codechecker@fe046668e`.
  Each CodeChecker commit was tested on its own with jest and eslint.
- functest 50 passed; server unit 147; report-converter unit 159; pycodestyle clean, pylint 10.00, mypy clean on 198 files with the Colorful Day venv's mypy.
- Both repositories have no tracked changes left.

## Open points

- D2 is untouched: recursive frames still share a `function::name` spelling.
- Memory of a call now reads as a raw dump, which is long; a label such as "`this` of a call to `Use::get()`, 2nd of 2" would need the frame's function in the table and the D6 count across calls, which is part of the D2 decision.
- The D6 count is by creation order only; it does not say where on the path each value was made, because the trace has no node for a pruned frame's call and the step labels of the nodes where they first appear are the same.
- Case 29's `Val` reads `reg_$25<unsigned int Val>`; the variable `Val` held another value later, so it no longer names it.
- The label line of a long function name still breaks inside a word at 900 px (ticket 05's open point), and a leading `->` can stand alone on a line; keeping it with its member made the browser break inside the identifier instead, so that was reverted.
- The What-If Unknown reason, which the server words, was not looked at for the new labels.
- D8 is untouched, including the low-contrast "Macro Expansion" label seen again in case 25.
