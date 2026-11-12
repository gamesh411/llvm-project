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
