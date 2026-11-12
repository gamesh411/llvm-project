# 09: A concrete example

**What to build:** A report reader asks for an example and sees, next to every row of "This path requires", one value that follows the Bug Path, including what each opaque call returned.
This ticket closes slice 3 of `../spec.md`.

**Blocked by:** 08

**Status:** resolved

- [x] A What-If check whose verdict is Feasible returns one model of the path as symbol and value pairs, only when the request asks for it.
- [x] A check with no What-If Constraints gives the example for the Bug Path as recorded, and with constraints the example satisfies them.
- [x] The example uses the existing per-call solver time limit. A timeout gives no example with a reason and does not change the verdict.
- [x] The request and result gain optional fields and the API minor version is raised once.
- [x] The example appears as a column of the requires list, labelled as one example of many, and is dropped when the What-If list changes.
- [x] Pointer values read null or non-null.
- [x] A report without solver input offers no example and says why.
- [x] Nothing about an example is stored.
- [x] Functional tests cover an example when asked, none when not asked, an example under a What-If Constraint, and the timeout through the patched-solver test.
- [x] Slice acceptance in a browser on the two demos and three LLVM reports from the triage study, with sizes and analysis time reported.
- [x] The CodeChecker documentation page describes the requires list and the example, including that an example is a model of what the analyzer recorded and not proof of a real execution.

## Comments

2026-11-13, ticket 09 worker.

Commits: `codechecker@22aee2ee6` (server, API 6.80, unit and functional tests), `1af850862` (comparisons read true or false), `ec38498fd` (the example in the panel), `fe046668e` (docs).
No Clang change, no DB migration, no `dev-loop.sh` change.

### API (6.79 to 6.80)

- `checkWhatIf(reportId, constraints, 3: bool withExample)`. An older client does not send it, which the server reads as false. Thrift ignores `optional` on function arguments, so the argument has none and the comment says so; the generated Python client takes it positionally, so the two calls in `test_permission_management.py` pass `False`.
- `WhatIfResult` gains `9: optional list<WhatIfExampleValue> example` and `10: optional string exampleReason`, and `WhatIfExampleValue` is `{1: string symbol, 2: string value}`, the value in decimal (a string, since an unsigned 64-bit or `__int128` value does not fit `i64`).
- Procedure followed as `codechecker_api/README.md` says: thrift file, `api_version.json`, stubs regenerated with `dev-loop.sh thrift` (docker), then `package` and `web`. No generated file is tracked or edited.

### Decisions

- The example is the model of the verdict's own solver call (the one with the What-If Constraints), taken only when the verdict is Feasible and the request asks. So asking adds no solver call (a unit test counts two calls either way), it uses the per-call limit, and it cannot change the verdict: a timeout gives the same Unknown as without asking, no example, and `exampleReason` "There is no example, because there is no verdict. The solver gave up on this path after 2000 ms.". Rejected: a separate solver call for the model, which would cost up to 2000 ms more for the same answer. The timeout is covered by the patched-solver unit test, as the lead decided after ticket 06; the functional tests cover asked, not asked, a constraint anchored and throughout, an infeasible path and a trace without SMT-LIB.
- Rows only (lead note 2): the server returns one value per entry of the last step's path condition, which is exactly the requires list, and nothing for other symbols. The value is `model.eval(term)` of the very term the entry's assertion constrains, found by walking the assertion Clang wrote (`and`/`or`/`not` down to the first comparison, whose left side is always the term, per `SMTConv::getRangeExpr`), so `m + n` is the solver's value of the sum and a comparison is its `ite` 0 or 1. An assertion of another shape is left out and the row reads "e.g. no value" (not seen on any report).
- Signedness without a type lookup: a bit-vector has none, so the server prints the reading (signed or unsigned) that lies in the analyzer's own range of that row, which Clang prints in the type's signedness. The model satisfies the range, so exactly one reading lies in it unless both are the same number. This gives `-2147483648` for the two-path demo's `int a` "not 0" and `4294967196` for case 29's `unsigned n`, and needs no type table for expressions.
- Display (`exampleValue` in `ConstraintTrace.js`): pointer null or non-null (type from the table, else the dump, as `readableRange`), comparison true or false, anything else the number, enums and `bool` included.
- State lives in `useWhatIf` beside the list: `askExample` sends the current list with `withExample`, and any change of the list (add, remove, reset) drops the example and any reply still in flight; checking the same list again keeps it. Jest covers that (`useWhatIf.test.js`). The verdict of the example call is not shown again; the reason is shown when there is no example.
- UI: a **Show an example** button under the "This path requires" hint, then a note "e.g. One example of many: values that follow this path[ with the N What-If Constraints below]. A model of what the analyzer recorded, not proof of a real execution." with **Hide**, and an "e.g. V" chip in `.panel-value` of every row. At 1400 px the chip sits beside a named row's range; below 1280 px (`compactHeader`) every chip takes its own line, and a row without a name always puts it on its own line. Lead note 4 check: beside the range at 900 px, `gd` "non-null e.g. non-null" wrapped while `lastgc` "null e.g. null" did not, which read uneven; and at 1400 px a label row (`this`, `P` in case 6) with range and chip side by side was too wide to share a line with the label, which then stood alone on its line. No text was shrunk.
- A report without SMT-LIB shows "No example: this report has no solver input for this path. Recording it needs a Clang built with Z3." and no button (`requires.solverInput` from `trace.smtlib`).
- Lead note 5: `readableRange` reads a range on a dump whose top operator is `<`, `>`, `<=`, `>=`, `==` or `!=` as "false" for `[0, 0]` and "true" for a range without 0, with the analyzer's range on hover as for every readable range, and leaves `[0, 1]` alone. The top operator comes from the existing `parseSymbolExpression`, so `(a < 5) + b` stays a number. Every place a range is shown (requires list, accumulated path condition, Other symbols, variables, What-If suggestions, line picker) goes through that one function. The expression is not rewritten.

### Verification

- Server unit 147 (8 new in `test_what_if.py`), functest 50 (4 new), the permission test file 5, report-converter unit 159, jest 137 in 8 suites (10 new, one new suite), eslint clean, pycodestyle clean, pylint 10.00, mypy clean (198 files). Clang lit not run: no Clang change.
- mypy: `/opt/homebrew/bin/mypy` gives the 19 missing-stub errors ticket 08 reported; the repo's `make mypy` uses the dev venv's `mypy~=1.19.0` and `types-PyYAML`, which I installed into the Colorful Day venv, and that run is clean.
- No tracked file left modified by the test runs in either repo.
- Browser, server restarted after the API change, cache-busting query on every load, `/Users/efulop/colorful-day-env/screens/t09-*`, 1400 and 900 px, window height 1000; on each a script checked that no element of the panel overflows and no chip or example line passes the panel's edges:
  - `t09-two-path-example-1400/900.png` (report 291): `a` and `b` "not 0 dropped e.g. -2147483648".
  - `t09-tmux-example-1400/900.png`, `t09-tmux-example-900-rows.png` (report 325): nine entry inputs; comparison rows now read true or false; `t09-tmux-this-step-1400.png` shows the accumulated path condition with true and false.
  - `t09-llvm-case6/25/29-example-1400/900.png`, below.
  - `t09-llvm-case29-what-if-1400.png`: `m == 100` at Step 14, Feasible, then the example: `n` e.g. 4294967196, which is 2^32 - 100. Removing the constraint drops the example (checked in the DOM: no chip, the button back).
  - `t09-llvm-case29-no-example-1400.png`: `n == 0` Infeasible, the example says "There is no example, because this path is not feasible with these What-If Constraints."
  - `t09-no-solver-input-900.png`: the `no_smtlib` fixture stored as `t09-no-smtlib` (report 381); the old `colorful-day-no_smtlib` run holds a version 1 trace, which shows no panel at all.
- `docs/web/images/constraints_requires.png` replaced by the tmux list with its example (1440 x 900, as before).

### Response time (checkWhatIf over HTTP from Python, server warm, no constraints, 5 calls each)

- Case 6 (report 356, 19 rows, the largest list of the three): example 11.6 to 21.4 ms, without 6.4 to 22.7 ms.
- Case 25 (report 301, 13 rows): example 9.7 to 24.7 ms. Case 29 (report 370, 5 rows): 5.8 to 18.1 ms.
- Study case 9 (`YAMLTraits.h:753`, 1,837 steps, stored as `t09-llvm-case9`, report 378): example 66.7 to 69.5 ms with 363 values, without 8.5 to 60.7 ms (first call cold 29.6 ms).
- Script `/Users/efulop/colorful-day-env/t09/timing.py`, output `timing.out` beside it.

### Sizes and analysis time

No Clang change, so the slice's figures are ticket 05's LLVM run, which tickets 06 to 09 did not change: plists 638,798,617 bytes (largest 27,040,071), user time 23,704 s, in the Comments of `05-caller-frame-variables.md`. LLVM was not analyzed again. The example adds nothing to plists or the database.

### The three LLVM reports: does the example make the unrealistic requirement easier to see?

- Case 6 (report 356, `SemaExprObjC.cpp:2772`): no. The deciding rows already read as one value each (`SuperLoc` 0, `this` non-null, `P` null), so the example repeats them ("e.g. 0", "e.g. null"). The only new numbers are on Other rows (shift results, `32 - result of countl_zero`), which the study did not ask about.
- Case 29 (report 370, `APInt.cpp:1363`): partly. The list says `n` not 0 and `m + n` 0; the example says `n` 1 and `m + n` 0, which makes the wrap concrete but does not show `m`, since `m` is not a row of its own (lead note 2). With `m == 100` as a What-If Constraint the example gives `n` 4294967196, and the unrealistic requirement, a sum that wraps to 0, is then explicit. Neither is a value for `m` alone.
- Case 25 (report 301, `MachineValueType.h:325`), chosen over case 1 because its rows are not all single values: no for the decisive row, `DstVT` (`Op.Node->ValueList[Op.ResNo].V.SimpleTy`) is 0 in the list and the example alike. `SrcVT`'s range `[0, 83] [85, 98] [101, 65535]` gets "e.g. 41964", an enum value no `MVT` has, which shows that the analyzer does not bound the enum but is not the case's question. Case 1 was checked too (script only): every row is one value or null/non-null, so the example repeats the list there as well.
- In short: on these reports the list already decides, because the analyzer mostly narrows a decisive value to one value. The example helps where a requirement is arithmetic over several inputs (case 29), most of all under a What-If Constraint.

### Open points

- A value of a symbol the path does not constrain on a row of its own (case 29's `m`) is never shown, by design; the reader works it out from the expression rows. Showing the atoms of compound rows would need a decision on whether such a value is "constrained".
- The comparison reading in the line picker was not seen in a browser: no picker row on the demo reports holds a comparison symbol. It goes through the same `readableRange`, which jest covers.
- `codechecker@22aee2ee6` changes the client argument list, and the page passes the new argument only from `ec38498fd`, so a page built at `22aee2ee6` alone would send the callback in the wrong place.
- The "What-If" in a reason can wrap at its hyphen in the 230 px panel ("What-\nIf"), as other reasons already could.
