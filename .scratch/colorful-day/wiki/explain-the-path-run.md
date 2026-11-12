# Explain the path: implementation run

Related: [use case review](use-case-review.md), [worker rules](worker-rules.md), [dev environment](dev-environment.md).
Sources: `../../explain-the-path/spec.md`, `../../explain-the-path/issues/`.

## 2026-11-12: order and constraints

On 2026-11-12 the lead decided to run tickets one at a time, in the order 10, 07, 01, 02, 03, 04, 05, 06, 08, 09.
Ticket 07 was pulled ahead of 01 because the assertions-on LLVM analysis was still using `build-colorful/bin/clang`, and ticket 01 has to rebuild that binary, while 07 changes only the web UI.
No worker rebuilds `build-colorful` while an analysis that uses it is running.

## 2026-11-12: ticket 10 accepted

On 2026-11-12 the lead accepted ticket 10 after viewing `/Users/efulop/colorful-day-env/screens/t10-tmux-1400.png`, at `codechecker@20176e7a5..d0a7b2c96` plus a commit retaking the panel screenshot, and `llvm-project@1014af8bae6e`.
Integer ranges read "not N", "N", "at least N" and "at most N" when the type's bounds are certain from the symbol dump, with the analyzer's range on hover.
Typedefs, enums, plain `char`, pointers and compound expressions keep the analyzer's range, and `long` is read as 64-bit only when a range reaches the 64-bit extreme.
The analyzer prints a comma between intervals, which the ticket text did not show, so the first formatter matched nothing in the browser until `codechecker@33b7bf41a`.
The "Show constraints" tooltip closes on click as of `codechecker@6776779b1`.
Checks the worker reported: eslint clean, jest 28 passed, functest 33 passed.
Left open: the worker could not open the line picker in the browser, so its readable ranges were checked by jest and code reading only, and there is no 900 pixel two-path screenshot.
The picker check was handed to the ticket 07 worker.

## 2026-11-12: ticket 07 accepted

On 2026-11-12 the lead accepted ticket 07 after viewing `/Users/efulop/colorful-day-env/screens/t07-highlight-1400.png`, `t07-marker-source-1400.png` and `t07-marker-source-900.png`, at `codechecker@fc52a8e3f` and `6ed777923`, and `llvm-project@0d25257d4671`.
Rows added or narrowed at the selected Path Step carry a `new` or `narrowed` tag and a coloured bar.
A control step that adds to the path condition with no event gets an icon in the report tree, an amber bar and an `assumes` tag in the source, and an "Assumed, no event" tag in the panel.
The worker measured "changed" against the closest earlier step with a different snapshot, because the printed path is not in node order.
A step click on LLVM report 3142 took a median 1100 ms before and 1090 ms after.
Checks the worker reported: eslint clean, jest 36 passed, functest 33 passed.
The ticket 10 carry-over passed: the line picker on `several-contexts.c` line 13 reads `a = not 0, p = 0` with the analyzer's range on hover.
Seen by the lead in the screenshots and left for a later polish: in the accumulated path condition the `new` tag wraps under its value where "Other symbols" keeps it on the value's line, and at 900 pixels the `assumes` tag in the source clips, which the amber bar covers for.
Not done: a legend for the tags.

On 2026-11-12 the lead started ticket 01 on Opus once no process was using `build-colorful/bin/clang`, because it spans Clang and both readers and has to verify how the analyzer conjures symbols.

## 2026-11-12: ticket 01 accepted

On 2026-11-12 the lead accepted ticket 01 after viewing `/Users/efulop/colorful-day-env/screens/t01-call-result-1400.png` and `t01-tmux-900.png`, at `llvm-project@c8ffa734edc1..640ad98c49b7` and `codechecker@00362f60c..958c17681`.
As of `llvm-project@6024f9416d07`, a trace has a `symbols` table, a list of dicts with one entry per atomic symbol, and the trace stays at version 2.
The spec's lead on the reason field held only in part.
A call result has no symbol tag, but so do other conjured values, and a checker that models a call, such as `malloc`, conjures a symbol identical to the analyzer's own.
The rule Clang applies as of that commit: a conjured symbol is `call_result` only when the Bug Path has a node tagged "Conservative eval call" whose statement is bound to that symbol in that frame, and every other conjured symbol is `other`.
Invalidation tags the symbol with the invalidated region and loop widening goes through invalidation, which is what ticket 02 builds on.
The worker's checks: emission off is byte-identical on 146 tmux plists and 17 others apart from the version string; emission on is equal after dropping the table and normalizing IDs; tmux plists grew 4.7% (4,991,542 to 5,226,320 bytes); Colorful Day lit 8 passed and 1 unsupported, functest 35, report-converter unit 155, server unit 119, jest 44.
`sarif-multi-diagnostic-test.c` failed once in 15 runs of `clang/test/Analysis` and did not reproduce, cause not found.
The opaque-call demo shows no label because its call returns void, so the worker added `demo/call-result.c`.
The worker also moved the path condition's change tag beside its range, which closes the wrap noted after ticket 07.
Left open: a result made in a callee the diagnostic pruned links by line and not to its call site, and analysis time and LLVM-run size were not measured, which ticket 03 owes.
Seen by the lead in the screenshot: a checker-modelled `malloc` result reads "origin not recorded line 11", which hides the statement text the table has, so ticket 02 was asked to show the statement for `other` symbols.

## 2026-11-12: ticket 02 accepted

On 2026-11-12 the lead accepted ticket 02 after viewing `/Users/efulop/colorful-day-env/screens/t02-llvm-case1-1400.png` and `t02-replaced-field-900.png`, at `llvm-project@2ddb35347d18..1add1cce508e` and `codechecker@21c2b0c56..9dd08b82e`.
As of `llvm-project@acd3806439a9`, a tagged conjured symbol is `invalidation` when the Bug Path's conservative eval call node for its statement and frame binds it to the region its tag names and the node before does not, and `loop_widening` when an untagged entrance of its block does the same.
Clang never dereferences a symbol tag, because checkers pass tags that are not memory; a new NFC `StoreManager::bindsSymbolTo` compares by address.
A checker that invalidates while modelling a call, such as `memcpy`, stays `other`, and lit covers that.
A derived symbol's entry has its parent and region, and the parent gets an entry of its own.
Labels read "`Tok.Kind` after `lex(&Tok)` may have changed it, line 11", "a global after `refresh()` may have changed it" and "value from `malloc(16)`, line 11", the last replacing the "origin not recorded" wording the lead flagged after ticket 01.
On study case 1 (`TokenAnnotator.cpp:3452`) the label reads "a value after `this->parse(prec::LogicalOr)` may have changed it, line 3486", which answers the triager's question of which call replaced the value; the field's name waits for ticket 04.
The worker's checks: emission off byte-identical on 146 tmux and 18 other plists; tmux plists grew 2.0% (5,226,237 to 5,329,381 bytes); Colorful Day lit 8 passed and 1 unsupported, functest 38, report-converter unit 155, server unit 119, jest 54.
`sarif-multi-diagnostic-test.c` did not fail in 2 full runs and 15 runs of its directory.
The worker fixed `map_trace_locations`, which mapped only a table's last location key.
A running server keeps the report converter it started with, so it has to be restarted after a reader change before storing.
Seen by the lead in the case 1 screenshot: the replaced pointer's range reads `[1, 18446744073709551615]` instead of non-null, because pointer detection reads the type from the dump and a derived symbol's dump has none, so ticket 03 was asked to carry pointer-ness in the table.

## 2026-11-12: ticket 03 accepted, slice 1 closed

On 2026-11-12 the lead accepted ticket 03 after viewing `/Users/efulop/colorful-day-env/screens/t03-llvm-case10-1400.png`, `t03-llvm-case27-900.png`, `t03-same-call-900.png` and `t03-tmux-accumulated-1400.png`, at `llvm-project@e7de190f44c3..ac2e9a89861e` and `codechecker@df256f397..7457ff20c`.
As of `llvm-project@e7de190f44c3`, a symbol entry has the symbol's canonical `type` and a `pointer` flag, which the worker chose over a bare flag because the type also gives derived symbols and typedefs their integer width.
As of `codechecker@e976b56bf`, a compound expression renders from the labels of its atoms and falls back to the whole raw dump when any atom has no label or the text is not read to its end.
Two `call_result` symbols with equal, uncut statement text are each tagged "another `f()` result, Step N"; invalidation and `other` symbols are not tagged.
One rule shortens statements over 40 characters to the outermost callee without arguments, replacing ticket 02's 32-character stopgap.
The CFG and States views show no symbols, so only the line picker gained labels.
`nearestStep` ties by column and then prefers an event over an arrow, so two calls on one line link to different steps.
The worker's checks: Colorful Day lit 9 passed and 1 unsupported, functest 39, report-converter unit 155, server unit 119, jest 85; emission off byte-identical on 146 tmux and 20 other plists.
`func-mapping-test.cpp` fails after a Clang rebuild until `clang-extdef-mapping` is rebuilt too.

Slice 1 measurement on the full LLVM run (3546 TUs, NDEBUG database, `-j8`, emission on), details in the Comments of `../../explain-the-path/issues/03-labels-everywhere-and-unrelated-values.md`:
plists total 627,216,851 bytes against 560,384,519 before the slice (+11.9%), largest 26,800,385 against 20,119,376.
User time was 23,339 s against 22,958 s for the first LLVM run (+1.7%); wall time is not comparable because the machine was shared.
The symbol table is 8.7% of trace bytes with CFG bodies and 25.7% without.
Of 51,280 conjured entries, 33,956 are `call_result`, 14,279 `invalidation` and 3,045 `other` (5.9%), the last led by `dynCastTo`, `memcmp`, `memcpy`, atomic `fetch_sub` and `simplify_type::getSimplifiedValue`, all checker or builtin modelled.
The lead judged 5.9% low enough not to spend another classification round on it.

Against the study's cases: case 10 (`APSInt.h:78`) is answered, the two `DestTy->isRealFloatingType()` results are tagged as different values; case 2 (`WhitespaceManager.h:343`) has its origin question answered but not the relation between cell counts and cells; case 27 (`CheckExprLifetime.cpp:1450`) is partly answered, `LK` reads as a `memcpy` value & 7 and not as `getEntityLifetime()`'s result.
Seen by the lead in the screenshots and passed to ticket 04: a compound expression's range stays raw (`LK` reads `[1, 18446744073709551615]`, clipped at 900 pixels) because an expression has no type in the table, and `Element{SymRegion{...}}` regions and extents stay raw dumps.
A same-call tag can link to "Arrow after step N", which reads oddly and was left open.

## 2026-11-12: ticket 04 accepted

On 2026-11-12 the lead accepted ticket 04 after viewing `/Users/efulop/colorful-day-env/screens/t04-llvm-case1-900.png`, `t04-llvm-case25-900.png` and `t04-tmux-accumulated-1400.png`, at `llvm-project@62bbbbf2c391..68340c213ea1` and `codechecker@89d2c578a..35d23b2e2`.
The analyzer's `getDescriptiveName` names nothing behind a pointer or `this`, because a field read through a pointer is stored as a field of `Element{SymRegion{p},0,T}`.
So as of `llvm-project@62bbbbf2c391`, `describeRegion` in `BugReporter.cpp` walks the region itself, and region value names, derived regions and invalidation origins all use it.
It follows a pointer only when the pointer's own value is the initial or replaced value of named memory, and gives no name to a pointee of a call result, a temporary, a computed index or a reinterpreted element.
The same commit adds a trace key `expressions` with the type and pointer-ness of each top-level constrained expression, kept out of `symbols` because the spec gives expressions no entry there.
As of `llvm-project@fe10c4a08577`, an extent entry has the region whose size it is, which the lead had not asked for.
As of `codechecker@03cf415ed`, the UI's parser of region dumps is removed, and names come only from the trace.
Study case 1 reads "`this->Current` after `this->parse(prec::LogicalOr)` may have changed it, line 3486"; case 25's deciding value reads `Op.Node->ValueList[Op.ResNo].V.SimpleTy`; case 18 is not answered, because its deciding value is a field of a temporary.
In the tmux report every row of the accumulated path condition renders from labels, such as `xx >= gd->linedata[py].cellsize` and `(py * 40) < size of *gd->linedata`.
The worker's checks: Colorful Day lit 9 passed and 1 unsupported, functest 40, report-converter unit 157, server unit 119, jest 92; emission off byte-identical on 146 tmux and 21 other plists; tmux plists grew 0.64% (5,388,483 to 5,422,895 bytes); 275 of 298 tmux region values have a name.
Left open: pointees of call results and temporaries have no name, metadata symbols have no name, and a constructor's invalidation statement prints as `*this`.

## 2026-11-12: ticket 05 accepted

On 2026-11-12 the lead accepted ticket 05 after viewing `/Users/efulop/colorful-day-env/screens/t05-caller-frames-900.png`, `t05-caller-frames-tags-1400.png` and `t05-llvm-case7-900.png`, at `llvm-project@3c0cd591fc73..5d04251d1913` and `codechecker@f664a3467..da6f46c19`.
As of `llvm-project@3c0cd591fc73`, a node has a `caller_variables` list whose entries start with an index into `stack_frames`, deltas match by frame and name, and `variables` is unchanged.
A global is written only under the innermost frame whose function uses it, and a frame with nothing to show is not written.
Caller variables' symbols get symbol table, `expressions` and SMT-LIB entries, so the worker expects ticket 06 to need no Clang change.
As of `codechecker@bbd3f31f7`, the Variables section has one group per frame, the step's own first and always open, callers collapsible and closed by default when there are more than 3.
A name from another frame is written `function::name` only when a variable of that name in another shown frame holds a different value.
With emission on, symbols are renumbered, because reading callers' parameters and globals creates their symbols earlier.
LLVM run (3546 TUs, `-j8`, `/Users/efulop/colorful-day-env/t05/reports`): plists total 638,798,617 bytes against ticket 03's 627,216,851 (+1.85%), largest 27,040,071, user time 23,704 s against 23,339 s (+1.6%, with a stuck `ReportCrash` process and web builds on the machine).
The caller list is 0.96% of trace bytes without CFG bodies.
The trace with the most stack frames is study case 9 (`YAMLTraits.h:753`) with 186 frames, at most 6 deep at once; the deepest stack anywhere is 16.
The worker's checks: Colorful Day lit 10 passed and 1 unsupported, functest 41, report-converter unit 159, server unit 119, jest 99; emission off byte-identical on 146 tmux and 22 other plists.
On study case 7 (`MemorySanitizer.cpp:1865`), which had no variable at its last step, the caller group shows `DataShadow` 0, which points at the loop that should have set it; the compiled-out assert the triager asked about cannot appear in a snapshot.
The worker found that the analyzer drops a caller's locals at the call unless the caller reads them afterwards, so on real code a caller group is often just the analyzed function's parameters.
Seen by the lead in the screenshots and passed to ticket 06: a variable whose range the analyzer dropped reads "no known range" in its group while the accumulated path condition shows the value with a `dropped` tag (`top::n` is 2 in the demo).
Left open: a 33-character function name breaks mid-word in a group heading at 900 pixels.

## 2026-11-12: ticket 06 accepted, slice 2 closed

On 2026-11-12 the lead accepted ticket 06 after viewing `/Users/efulop/colorful-day-env/screens/t06-llvm-case1-900-verdict.png`, `t06-llvm-case25-900-verdict.png` and `t06-caller-ambiguous-1400.png`, at `codechecker@4a5db1481..e92a2d384` and `llvm-project@4bf1528255ed..d480d5b7c777`.
It needed no Clang, Thrift or database change.
As of `codechecker@7c268620e`, a What-If name resolves on the server, in `what_if.py` only, to a variable of the step's frame or a calling frame, written alone or as `function::name`, and otherwise to memory the symbol table names; a variable hides memory of the same name.
A name with several values at a step gives Unknown and lists them.
A derived value counts as a name of its memory, so "Holds throughout" covers a field before and after a call replaced it, and an anchored check on such memory after the call is Unknown.
The page's suggestion list mirrors the server rule, and a file of names written by a server unit test (`what_if_names.json`) is compared by jest, which the worker chose over a new RPC to keep the one API bump for slice 3.
The grammar accepts subscripts that are names, beyond the spec's constant subscripts, because Clang names study case 25's value `Op.Node->ValueList[Op.ResNo].V.SimpleTy`.
As of `codechecker@64f180381`, a variable the analyzer dropped shows its last path-condition range with a `dropped` tag.
`codechecker@4a5db1481` fixes a mypy error that predates the ticket.
The worker's checks: functest 46, server unit 139, report-converter unit 159, jest 117, Colorful Day lit 11 passed and 1 unsupported.

Study table A4 measured again on ticket 05's LLVM run with the study's `measure.report()` and `/Users/efulop/colorful-day-env/t06/a4.py`:
What-If can address 39.0% of LLVM path-condition entries against 11.4% under the study's rule, and 67% against 36% on tmux.
84.8% of LLVM entries read as a name or label and not a raw dump, and 26.9% have a display name.
The share the panel names by a variable stayed at 9.3%, since caller variables added 8 entries.
1220 of 1225 reports have at least one What-If name.

What-Ifs on study cases: case 1, `this->Current == null` throughout, is Infeasible at Step 3 and settles the case; case 25, `VT != 0`, is Infeasible where the study got Unknown and settles the case; case 7, `DataShadow != 0`, is Infeasible but only restates the path, since the deciding assert is compiled out.
Left open: no spelling picks "the value after `parse()`" for an anchored check; memory is told apart by name only, so two functions' `this->Current` are one name; 9.3% of stack frames have a function name that cannot be typed before `::`.
Seen by the lead in `t06-caller-ambiguous-1400.png`: the Unknown reason reads "at Step 10.n names 2 values" with no space after the period, passed to ticket 08 to check.

## 2026-11-13: ticket 08 implemented

On 2026-11-13 the ticket 08 worker built the "This path requires" list at `codechecker@08cd17806..8414ea383`, with no Clang, server or API change.
The reader groups the path condition of the last Path Step by the symbol table into entry inputs, call results, replaced values and other, and gives each row the first Path Step that shows it as it ends, with that step's function and whether it is a silent step.
A compound value goes by its atoms when they agree, so case 29's `m + n` is an entry input.
Checks the worker reported: jest 127 in 7 suites, eslint clean, functest 46 passed, pycodestyle clean, pylint 10.00; mypy reports 19 errors that are missing stubs in the venv.
The decision on where it sits and the control step rename are in [web UI decisions](web-ui-decisions.md); the Comments of `../../explain-the-path/issues/08-this-path-requires-list.md` have the rest.
On the three LLVM cases the worker analyzed again as `t08-llvm`: the list shows the decisive requirement of case 6 (`SuperLoc` 0, first row) and of case 29 (`m + n` 0, an entry input), and of case 27 (`LK` 7) only under Other, since its call was modelled by a checker.
The ticket 06 spacing bug ("Step 10.n") was already fixed by that ticket; a test now guards it.

## 2026-11-13: ticket 08 accepted

On 2026-11-13 the lead accepted ticket 08 after viewing `/Users/efulop/colorful-day-env/screens/t08-llvm-case6-requires-900.png`, `t08-tmux-requires-1400.png` and `t08-llvm-case29-requires-1400.png`, at `codechecker@08cd17806..8414ea383` and `llvm-project@5c56e6603aa2`.
The lead accepted the worker's placement, a "This step" and "Whole path" toggle, recorded in [web UI decisions](web-ui-decisions.md), because What-If keeps its place and the last step's rows are not shown twice.
The lead left a checker-modelled value such as case 27's `LK` under Other and did not add a group for it, since Clang does not record that such a value is a call's result.
Seen by the lead in the screenshots and passed to ticket 09: a comparison row reads `xx >= end` with the value 0, which a reader has to decode as "false".
Also seen: in case 29 a row is named `Val`, a parameter of an inlined callee, under Entry inputs, because a value goes by the variable that first held it.
Not seen in a browser: the ungrouped list for a trace without the symbol table, which jest covers.

## 2026-11-13: ticket 09 accepted, slice 3 and the spec closed

On 2026-11-13 the lead accepted ticket 09 after viewing `/Users/efulop/colorful-day-env/screens/t09-llvm-case29-what-if-1400.png`, `t09-tmux-example-900-rows.png` and `t09-tmux-this-step-1400.png`, at `codechecker@22aee2ee6..fe046668e` and `llvm-project@e6a65ee237ff`.
It needed no Clang change and no database migration, and nothing about an example is stored.
As of `codechecker@22aee2ee6`, the API is 6.80: `checkWhatIf` has a third argument `withExample`, and `WhatIfResult` has optional `example` (symbol and decimal string value pairs) and `exampleReason`.
The example is the model of the verdict's own solver call, so asking for it adds no call and cannot change the verdict; a timeout gives no example and a reason.
The server returns a value only for entries of the last step's path condition, each the solver's evaluation of the term that entry constrains.
It prints the signed or unsigned reading that lies inside the analyzer's range for that entry, which needs no type table.
A new Thrift argument breaks callers positionally: a page built at `22aee2ee6` alone would send its callback in the wrong place, and the page passes the argument from `codechecker@ec38498fd`.
As of `codechecker@1af850862`, `readableRange` reads a range of a comparison as "true" or "false", with the analyzer's range on hover.
As of `codechecker@ec38498fd`, "Whole path" has a "Show an example" button, each row gets an "e.g. V" chip, and any change of the What-If list drops the example.
The worker's checks: server unit 147, functest 50, report-converter unit 159, jest 137, eslint, pycodestyle and pylint clean, mypy clean on 198 files with the repo's pinned mypy installed into the Colorful Day venv; the 19 mypy errors ticket 08 reported came from Homebrew's mypy on PATH.
An example request took 12 to 21 ms on study case 6 and 67 to 70 ms on case 9's 1,837-step trace with 363 values.
On the study's cases the example repeats the list where the analyzer already narrowed the deciding value to one value (cases 1, 6, 25), and helps on case 29, where `n` not 0 and `m + n` 0 become `n` 1, and under `m == 100` `n` becomes 4294967196, which makes the unsigned wrap explicit.
Left open: a symbol that is not a row of its own, such as case 29's `m`, gets no value; a single-valued row shows a chip that repeats its value; the comparison reading in the line picker was not seen in a browser.
With this ticket every ticket of `../../explain-the-path/issues/` is resolved.
