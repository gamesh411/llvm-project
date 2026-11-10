# 07: "Holds throughout" and first dead step

**What to build:** A report reader can state that a constraint holds across the whole Bug Path, which tests claims like "this global is never null" even after opaque calls replace its value.
An Infeasible verdict names the earliest Path Step where the path dies.

**Blocked by:** 05

**Status:** ready-for-agent

- [x] A "holds throughout" toggle applies a term to every value the variable takes across the Bug Path.
- [x] A global reassigned by an opaque call is constrained both before and after that call when the toggle is on, and only at the anchored value when it is off.
- [x] An Infeasible verdict names the earliest Path Step whose accumulated path condition, combined with all What-If Constraints, is unsatisfiable.
- [x] That step can come before the step the constraint is anchored to, and the UI displays this correctly.
- [x] The named step is selectable from the verdict.
- [x] A CodeChecker functional test covers both toggle states and the first dead step through the API.
- [x] The behavior is checked in a real browser.

## Comments

### API contract (6.78, `codechecker@6325f9164`)

Additive, regenerated with `dev-loop.sh thrift`.

```
WhatIfConstraint:
  3: optional bool holdsThroughout, // unset means false
WhatIfResult:
  7: optional i64 firstDeadStep,    // `order` of a step, set only when verdict is INFEASIBLE
```

No plist or Clang change: the opaque-call case needed only a new demo.

### Rules implemented

Values a term applies to:

- Anchored (toggle off): the variable's value at the anchor step, as before.
- Holds throughout: every distinct value (`kind` and `value`) the variable has at any step that lists it. Steps where it is not listed are skipped. Its anchor only records where it was typed.
- A symbolic value gets a solver formula. A concrete value is decided directly, as in 06, so an `integer` or `address` value that breaks the term makes the path dead where the variable holds it. A symbol without `smt` or an address against a non-zero number is Unknown for the whole check, as anchored terms already were, naming that constraint.
- Holds throughout on a variable that no step lists is Unknown: "`w` has no tracked value at any Path Step."

Where a term starts to apply (its `since` step):

- A symbolic value: the first step whose `smt_declarations` declare every symbol of its `smt` term. A symbol never changes value, so the term holds wherever the symbol exists, which can be before the anchor. It does not apply before that, so a term that contradicts itself (`g > 3 && g < 2`) kills the path where its value appears, not at step 0.
- A concrete value: the start of the uninterrupted run of steps up to the anchor (or, throughout, up to the first step holding it) where the variable holds that same value.
- A step's constraint set is its own `smt_assertions` (its accumulated path condition) plus every applied term whose `since` is at or before it. The verdict is the last step's set, unchanged from 05 and 06.

First dead step:

- Searched only when the verdict is Infeasible, which proves the last step dead.
- The path condition's ranges only narrow along a path, and applied terms are never taken back, so deadness is monotone in the step and a binary search over steps in `order` finds the earliest one.
- A search call the solver gives up on counts as alive, so the named step is always one proven dead. If the solver gives up, it may be later than the true first.
- The server names the earliest `order`. Control edges carry their end node's snapshot (ticket 04), so this is often the edge into the line of an "Assuming" event, e.g. order 5 (edge into line 11) rather than order 7 ("Assuming 'g' is null") in `opaque_call`. The UI resolves it with the same rule as line selection: same line, same snapshot is one choice, the event if there is one. So the reader sees "Step 3".

Solver work per check:

- Each call is still at most `WHAT_IF_SOLVER_TIMEOUT_MS` (2000 ms).
- Calls: Baseline, verdict, then at most ceil(log2(N)) for N steps (9 calls in total for 100 steps, checked in `test_search_takes_logarithmically_many_solver_calls`).
- The search also has a wall-clock budget `WHAT_IF_SEARCH_BUDGET_MS` (4000 ms). Each search call gets min(2000, what is left), and when it runs out the earliest step proven dead so far is named.
- So an API worker is held at most 2000 + 2000 + 4000 = 8000 ms per check.
- Every step's assertions are parsed with the union of all steps' declarations, since symbol IDs are unique in a report.

### Fixture and dev loop

- New `demo/opaque-call.c`: `g` is checked non-null, `refresh()` (no body) replaces it with `derived_$9`, and the path assumes that null. `dev-loop.sh fixture` writes `web/tests/projects/constraint_trace/opaque_call/`. As in 06, regenerating changed only the `clang_version` line of the other five plists, so those were restored.
- Dev server: `DEMO=.../demo/opaque-call.c RUN_NAME=colorful-day-opaque dev-loop.sh analyze` and `store`. It is report 14 there.

### Web UI

- "Holds throughout the path" checkbox under the input, with a tooltip. It applies to what is typed next and stays set. A listed throughout constraint is headed "Throughout" (tooltip: where it was typed) and is never bold as "here".
- An Infeasible verdict reads "It dies at **Step 3**, the first step whose path condition contradicts it." When the single constraint is anchored after that step: "It dies earlier, at **Step 2**, whose path condition already contradicts it." The step name is a button that selects the step, scrolls to its line and highlights its bubble. The verdict stays.
- The selected dead step shows a "Path dies here" mark beside its heading.
- Picky fixes along the way, seen at 900px: an inline expression broke at its own spaces (`g` / `!= null`), so it is now an inline block that moves to the next line whole. A long range interval such as `[1, 18446744073709551615]` was clipped with no wrap, so an interval now breaks inside only when it alone is wider than the column (a 03 rule).

### Housekeeping: `dev-loop.sh stop` hang

- Reproduced on the server left from ticket 06. Eleven seconds after `stop`, 23 processes still listened. `sample` (py-spy needs root on macOS) showed every stuck API worker with its main thread in `accept()` and a Z3 `scoped_timer` thread alive. Each `curl` to the port released exactly one worker.
- Cause: API workers are preforked `HTTPServer`s on one listening socket. Every worker wakes for each connection, and the losers block in `accept()`. Once Z3 has run, a worker has a second thread. The process-directed SIGINT can land on that thread, so the main thread's `accept()` is not interrupted, and Python runs the handler only at the next connection. The main process joins workers in order, so one stuck worker stalls the whole shutdown.
- Not reproduced by a fresh server with 30 checks or a short browser session, since both conditions must meet. Direct SIGINT to individual workers after 40 checks reproduced it: 2 of 11 Z3 workers stuck, 0 of 10 without Z3.
- Fix (`server.py`): `serve_forever_with_shutdown_handler` sets a 0.5 s timeout on the listening socket. A losing `accept()` then raises `TimeoutError`, which `socketserver` treats as no request, and the loop returns to run the handler. Accepted sockets stay blocking (checked). After the fix: 0 of 36 Z3 workers stuck over three rounds, and `stop` with a browser connected after UI checks takes 6 s.
- `dev-loop.sh stop` now waits up to 30 s for the wrapper to exit. It fails loudly if the wrapper is still running or the port is taken by something else, so `server` right after never meets the old one. The old code made it fail as intended.
- An orphaned server main process from ticket 06's kill-by-port (ppid 1, started 21:29) was still running. It was stopped with SIGTERM.

### Traps

- Vue's whitespace condensing drops the space next to an interpolation that starts or ends a `<template>` block. The verdict read "throughout.It dies" and "it.The bug". Keep literal text at both ends of such blocks.
- `npx` under the user's shell recurses into the lazy nvm function. Unset `node npm npx` and call `node_modules/.bin/eslint` directly.

### Test results (2026-11-10)

- Server unit: 98 passed (`test_ccldap.py` excluded, no `ldap`). 34 of them are in `test_what_if.py`; the 16 new ones were written first and 13 failed before the change (the other 3 hold for the anchored path already).
- `dev-loop.sh functest`: 28 passed (23 before). `store` 7/7. `report_viewer_api` 66/67, the known Clang 14 expectation. Report-converter unit: 136 passed. `dev-loop.sh lit`: 4 passed, 1 unsupported (no-z3). Clang was not touched, so `clang/test/Analysis` was not run.
- `pycodestyle` clean and `pylint` 10.00 on `what_if.py`, `server.py`, the unit test and the functional test. `eslint` clean on the four touched UI files.
- No tracked files changed by test runs in either repository.

### Verification

Screens in `/Users/efulop/colorful-day-env/screens/`, driven with `chrome-devtools-axi`:
- `07-toggle-off-feasible-1400.png`: `g != null` at Step 1, toggle off, Feasible.
- `07-toggle-on-infeasible-{1400,1100,900}.png`: the same, toggle on, Infeasible, dies at Step 3.
- `07-dead-step-selected-{1400,1100,900}.png`: after a real click on "Step 3", the panel shows Step 3 with "Path dies here".
- `07-dies-before-anchor-{1400,1100,900}.png`: two-path `b == 0` at Step 4, "It dies earlier, at Step 2".

