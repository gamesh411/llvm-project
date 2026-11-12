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
