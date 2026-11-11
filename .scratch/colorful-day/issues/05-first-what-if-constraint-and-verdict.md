# 05: First What-If Constraint and Path Verdict

**What to build:** A report reader types one `variable op value` What-If Constraint at the selected Path Step and presses Check.
The CodeChecker server solves it with Z3 and returns a Feasible or Infeasible Path Verdict along with the Baseline Verdict.
On the two-path example, `b == 0` returns Infeasible and the result is worded as being about this path.

**Blocked by:** 03

**Status:** resolved

- [x] With a Z3-enabled Clang, the plist carries SMT-LIB built with the same symbol encoding as the Z3 crosscheck.
- [x] Without Z3, Clang still emits readable ranges, and a check reports Unknown instead of failing.
- [x] The Python Z3 package is a CodeChecker server dependency.
- [x] A new Thrift method takes a report ID and What-If Constraints and returns a Path Verdict and a Baseline Verdict, and requires only product view permission.
- [x] Solving applies a short fixed timeout.
- [x] A variable resolves to the symbol it holds at the anchored Path Step.
- [x] Solving starts only when the reader presses Check.
- [x] A Baseline Verdict that is not Feasible is shown separately from the result of the reader's constraint.
- [x] What-If Constraints are not written to the database.
- [x] Every verdict is worded as being about this path, not this bug.
- [x] A CodeChecker functional test covers Feasible, Infeasible and a non-Feasible Baseline Verdict through the API.
- [x] The two-path `b == 0` case is checked in a real browser.

## Comments

### Plist contract additions (still `version` 1)

Purely additive. With a Z3-enabled Clang every step dict also has:

```
smt_declarations: array of string, one `(declare-fun reg_$1 () (_ BitVec 32))` per
  analyzer symbol that path_condition or a variable's term refers to, sorted by symbol ID
smt_assertions: array of string, one `(assert ...)` per path_condition entry, in its order;
  a string can span several lines (Z3's printer)
```

and each `variables` entry of kind `symbol` whose type is an integer, enum or pointer also has `smt` (the SMT-LIB term, e.g. `reg_$1`) and `smt_signed` (whether `<` on it is signed).
Both keys are present, possibly empty, whenever Clang has Z3; absent means a Clang without Z3 (`PathDiagnosticConstraintSnapshot::HasSMTLIB`), so a path with no constraints is not mistaken for one.
The encoding is the crosscheck's: `getCrosscheckRangeConstraint` (`Z3CrosscheckVisitor.h`) is now shared by `Z3CrosscheckVisitor::finalizeVisitor` and the snapshot, and symbol names come from `SMTConv::fromData` (`kindStr` + ID, matching the `reg_$N<...>` dumps).
On `demo/z3-refuted.c` Z3 finds the emitted last-step SMT-LIB unsat and crosscheck drops the report, so the two agree.
`symbol_ranges` stays human-readable only.

### CodeChecker contract additions (API 6.76)

- `checkWhatIf(reportId, list<WhatIfConstraint>) -> WhatIfResult`, `PRODUCT_VIEW`. `WhatIfConstraint{pathStep: the step's order, expression}`; `WhatIfResult{verdict, reason?, baselineVerdict, baselineReason?}` with enum `PathVerdict {FEASIBLE, INFEASIBLE, UNKNOWN}`. A missing report is `RequestFailed(DATABASE)`.
- No `holdsThroughout` or first-dead-step fields yet; 07 adds them as optional fields.
- Evaluation is `web/server/codechecker_server/api/what_if.py`. Both verdicts are solved over the last step's (highest `order`) assertions, which hold the whole accumulated path condition; the anchor step only decides which `smt` term a name means. Declarations of the anchor step and last step are unioned.
- The term is read back from Z3 by parsing `(assert (= T T))` with the declarations, which gives the width; the value must fit the type or the result is Unknown.
- `WHAT_IF_SOLVER_TIMEOUT_MS = 2000` per solver call, two calls per check. A fresh `z3.Context` per check, since API workers may run threads.
- Parser: `parse_constraint` tokenizes and calls `_parse_term` once; 06 adds the `&&` loop there and `null` as a value token. Syntax errors are Unknown with "Cannot read the constraint: ..." for now; 06 may want them as a separate field.
- Concrete (`integer`/`address`) variables give Unknown "not supported yet" (06's direct comparison).
- `z3-solver~=5.3` in `web/requirements.txt`; `dev-loop.sh env` picks it up (the existing venv got it by hand).

### Fixtures and dev loop

- `dev-loop.sh fixture` now also writes `no_smtlib/` (the `with_snapshots` plist with every SMT key removed, which is what a Clang without Z3 writes, so no second Clang build) and `z3_refuted/` from `demo/z3-refuted.c` (`x * x == -1`: the range solver accepts it, Z3 refutes it; analyzed without crosscheck so the report exists).
- `dev-loop.sh lit` runs `constraint-snapshots-smtlib.c` (REQUIRES: z3) and `constraint-snapshots-no-z3.c` (UNSUPPORTED: z3). The latter never runs here; the non-Z3 path was checked by a `-fsyntax-only` compile of `BugReporter.cpp` with `LLVM_WITH_Z3` removed from a copied `llvm-config.h`, and by preprocessing that the Z3 block is gone.

### Web UI

- The panel has a "What if" footer below the scrolling snapshot: input, Check button, verdict. Nothing is solved until Check (or Enter in the form). Changing the selected step clears the verdict and keeps the text.
- Verdict texts all say "this path"; Infeasible adds "The bug may still be reachable through another path."
- A non-Feasible Baseline Verdict is shown as its own amber box "Without your constraint: ..." above the verdict. When the verdict is Unknown with the same reason as the baseline (no SMT-LIB), only the baseline box is shown.

### Traps

- `CHECK-NOT` placed before the first `CHECK` only covers the text before that first match, so the `CHECK-NOT: MISSING` lines of tickets 02 to 04 checked nothing. They are `--implicit-check-not=MISSING` now (`llvm-project@81e5c106ace7`); all still pass.
- In `Report.vue`'s non-scoped `<style>` block, `:deep(...)` is emitted literally and the rule is dropped; upstream's `.cm-line:hover` and blame rules there never applied. Left alone; use plain selectors in that block.
- The browser kept a cached bundle after `dev-loop.sh web`; `chrome-devtools-axi stop` and `start` fixed it. `resize` only works after a page is open.
- The workspace product database of a functional test is `<workspace root>/global_simple_server/<basename of TEST_WORKSPACE>.sqlite`, not `<product>.sqlite`.

### Housekeeping

1. Closed-panel dotted line (`codechecker@0010a3dec`): the editor container is only as wide and tall as the code, and a line click in constraints mode focused CodeMirror, whose default `cm-focused` dotted outline traced that box. Reproduced in `05-housekeeping-repro-1400.png`; fixed by dropping the outline on the read-only editor (`05-housekeeping-after-1400.png`, same as `02b-off-1400.png`). Making the container fill the column was tried and rejected: bubbles then grow to their 640px max-width and stop lining up, unlike `02b-off`. The active-line highlight still ends at the code's width while the editor is focused (upstream behavior).
2. `store` three times after `functest`: 7/7 each time, so the 3 instead of 6 clang-tidy reports did not reproduce and the cause is still unknown.
3. Two pre-existing pylint W1203 warnings in `report_server.py` fixed separately (`codechecker@88d2d5ece`).

### Test results (2026-11-10)

- `dev-loop.sh lit`: 4 passed, 1 unsupported (no-z3). `clang/test/Analysis`: 1265 tests, the only failure is the user's untracked `bstring-UninitRead-partial-init.c` (`func-mapping-test.cpp` passes after `dev-loop.sh clang`).
- `dev-loop.sh functest`: 16 passed. `authentication/test_permission_management.py`: 5 passed, including `test_what_if_needs_only_product_view`. Server unit tests: 71 passed (`test_ccldap.py` excluded: no `ldap` module in the venv).
- `store`: 7/7 three times. `report_viewer_api`: 66/67 (the known Clang 14 expectation). report-converter unit: 136 passed; no tracked files changed.
- Mutations checked: a DB write in `checkWhatIf` fails `test_check_writes_nothing_to_the_database`, and `__require_store` in place of `__require_view` fails the permission test.
- `pycodestyle`, `pylint` (10.00 on `report_server.py` and `what_if.py`), `eslint` on the two Vue files, `clang-format-diff` on the C++: clean.

### Verification

Screens in `/Users/efulop/colorful-day-env/screens/`: `05-b-eq-0-infeasible-{1400,1100,900}.png` (two-path, Step 2, `b == 0` Infeasible), `05-b-eq-5-feasible-1400.png`, `05-step1-b-eq-0-1400.png` (same term anchored at Step 1, also Infeasible since `b` holds one symbol), `05-unknown-variable-1400.png`, `05-syntax-unknown-1400.png`, `05-baseline-infeasible-1400.png` (z3_refuted fixture stored on the dev server), `05-no-smtlib-1400.png`, `05-typed-not-checked-1400.png` (typed, no verdict before Check), `05-housekeeping-*.png`.
