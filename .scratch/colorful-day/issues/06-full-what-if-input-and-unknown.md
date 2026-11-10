# 06: Full What-If input and Unknown handling

**What to build:** A report reader can express a complete hypothesis with terms joined by `&&`, `null` values and constraints on several Path Steps, helped by name suggestions.
Input that can't be evaluated gets a specific explanation instead of a wrong answer.

**Blocked by:** 05

**Status:** ready-for-agent

- [x] The grammar accepts `variable op value` terms joined by `&&`, with `==`, `!=`, `<`, `<=`, `>`, `>=`, and integer literals or `null` as values.
- [x] Syntax errors appear beside the input, and the reader's text is kept.
- [x] What-If Constraints on several Path Steps all apply together in one check.
- [x] The input suggests variable names from the selected step's Constraint Snapshot.
- [x] A term on a concretely known value is decided by comparing against that value, so `p == 0` is Infeasible when `p` holds `&x`.
- [x] A variable with no tracked value at the step gives Unknown and names that variable.
- [x] A solver timeout gives Unknown and says so.
- [ ] A CodeChecker functional test covers each verdict and error path through the API.
- [x] Multi-step input and error messages are checked in a real browser.

## Comments

### API contract (6.77, `codechecker@da8c060ca`)

Additive, regenerated with `dev-loop.sh thrift`.

```
struct WhatIfSyntaxError {
  1: i64    constraintIndex, // position in the request's constraint list
  2: string message,         // names tokens in backticks, e.g. found `=`.
  3: i64    offset,          // character offset in that expression
}
WhatIfResult:
  5: optional WhatIfSyntaxError syntaxError,
  6: optional i64               reasonConstraintIndex,
```

- Every expression is parsed before anything is solved. The first unreadable one gives `syntaxError`, `verdict` UNKNOWN, `reason` "Cannot read the constraint: ..." for old clients, and the Baseline Verdict as usual. That holds on reports without a trace or SMT-LIB too, so a typo is always pointed out.
- `reasonConstraintIndex` says which constraint an Unknown reason is about (no tracked value, untyped symbol, address against a number, value out of range, missing step). It is unset for path-level reasons such as a timeout.
- All constraints in one request apply together over the last step's assertions, as in 05. The request is still a list of `{pathStep, expression}`, so 07 can add an optional `holdsThroughout` field per constraint and an optional first-dead-step field on the result without breaking anything.
- `null` is 0. Concrete values are decided in Python and passed to Z3 as `true` or `false`, so the Baseline Verdict and solver reasons still apply: `integer` compares as a mathematical integer, `address` is non-null (`== 0` false, `!= 0`, `> 0`, `>= 0` true), and an address against a non-zero number is Unknown.
- A `symbol` variable without `smt` (a type the encoding skips, e.g. float) is now Unknown "whose type the check cannot reason about", instead of 05's "concrete value not supported yet".

### Fixture and dev loop

- New `demo/concrete-value.c` (`p` holds `&x` while `q` is assumed null) and fixture `web/tests/projects/constraint_trace/concrete_value/`, written by `dev-loop.sh fixture`. Regenerating also rewrote the other four plists, but only their `clang_version` line changed, so those were left at their committed version.
- On the dev server: `DEMO=.../demo/concrete-value.c RUN_NAME=colorful-day-concrete dev-loop.sh analyze` and `store`. It is report 13 there.

### Web UI

- The What-If state is `useWhatIf()` (`composables/useWhatIf.js`), owned by `Report.vue` and reset when the open report changes, so constraints survive step changes and closing the panel but nothing else. The section is its own component, `WhatIfSection.vue`.
- Check sends the listed constraints plus the typed one anchored at the selected step. The typed one joins the list only if the server can read it; otherwise the error appears under the input in red, the text stays, and the caret moves to `offset`. Check with an empty input re-checks the list. Removing a row clears the verdict, since it was about the old list.
- The list is "Checked together", one row per constraint with its step heading (bold when it is the selected step) and a remove button. The row an Unknown reason is about is marked. With one constraint the verdict names it and its step, with several it says "these N assumptions together".
- Suggestions: a listbox teleported to `body` with fixed positioning, so neither scroll area clips it. It opens upwards near the window bottom. It lists the selected step's variables matching the word at the caret wherever a name belongs (start, or after `&&`), with each one's value or known range. Arrow keys move, Enter or Tab accepts, Escape closes. On an empty input it opens only on ArrowDown, so Enter there still checks.
- Lead finding from `05-b-eq-0-infeasible-1400.png`: the snapshot and the What-If section now share the panel height. The snapshot keeps at least 120px, the What-If section at most 55%, each scrolls on its own, and an edge that hides content gets a 12px shadow (`useScrollShadows`). The hint under "What if" is hidden once there is a list. Shadows are separate overlay elements, because the sections' own backgrounds would cover a background-attachment shadow.
- Server messages quote names and operators in backticks, and the UI renders those as inline code.

### Traps

- 05's timeout test was a lucky slow query. Its "64-bit semiprime" is unsat, and Z3 5.4 proves it in about 60 ms with no timeout, so it passed only because 50 ms happened to be shorter. It now swaps `z3.Solver` for a subclass whose `check` returns `unknown` with reason `timeout`, and checks that every solver call was given `WHAT_IF_SOLVER_TIMEOUT_MS`.
- A forced timeout through the API would need a test-only hook in the server process, which I did not add. So the timeout path is covered by the unit test only, and the functional-test checkbox stays unticked for that reason. Every other verdict and error path goes through the API in `test_constraint_trace.py`.
- `role` given to `v-text-field` also lands on its outer `v-field`, so the page announced two comboboxes. The role is set on the `<input>` in `onMounted`, and the `aria-*` attributes go to the input on their own.
- `dev-loop.sh stop` kills only the wrapper PID. With a browser connected, the server then sits in "graceful clean-up" for more than 10 s and the next `server` reports "already listening" while `store` gets connection resets. I waited and then killed whatever still held the port.
- `ReportDetail.vue` loads the report only on mount, so a router push to another `report-id` changes the URL but not the report (upstream). The reset was checked through the "Found in" selector instead. After switching there, the URL keeps the old `report-id` (upstream, not touched).

### Test results (2026-11-10)

- Server unit: 82 passed (`test_ccldap.py` excluded, no `ldap`), 18 of them in `test_what_if.py`. They were written first, and 9 failed before the change.
- `dev-loop.sh functest`: 23 passed (16 before). `dev-loop.sh lit`: 4 passed, 1 unsupported (no-z3). Clang was not touched, so the whole `clang/test/Analysis` was not re-run.
- `store` 7/7. `report_viewer_api` 66/67, the known Clang 14 expectation. report-converter unit: 136 passed. No tracked files changed by the runs.
- `pycodestyle` and `pylint` clean on `what_if.py`, `test_what_if.py` and the functional test. `eslint` clean on the five touched or new UI files.

### Verification

Screens in `/Users/efulop/colorful-day-env/screens/`, driven with `chrome-devtools-axi`:
`06-syntax-error-1400.png` (`b = 0` at Step 2, error under the input, text kept, earlier verdict still shown), `06-two-steps-feasible-1400.png`, `06-three-infeasible-1400.png`, `06-multi-unknown-{1400,1100,900}.png` (the row `q` is about is marked, the snapshot shadow shows it scrolls), `06-many-900.png` (five rows, both areas scroll with shadows), `06-suggestions-1400.png`, `06-concrete-address-infeasible-1400.png` (`p == 0` while `p` holds `&x`), `06-baseline-infeasible-1400.png`, `06-no-smtlib-1400.png`.
Not seen in the browser: a solver timeout, which cannot be forced there.


### Lead decision on the timeout checkbox (2026-11-10)

The timeout is covered by a deterministic unit test in `web/server/tests/unit/test_what_if.py`, not through the API.
Adding a test-only hook to the server to force a timeout through the API was rejected, because it would put test code into a production path for a case that the unit seam already covers fully.
The checkbox stays unticked so the gap remains visible.
