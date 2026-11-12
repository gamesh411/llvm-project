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
