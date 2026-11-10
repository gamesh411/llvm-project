# 03: Complete the Constraint Snapshot

**What to build:** The side panel shows a report reader everything the analyzer knew at a Path Step: variable names mapped to symbols or concrete values, raw symbols that no variable names, what is known at this step, and the accumulated path condition so far.

**Blocked by:** 02

**Status:** ready-for-agent

- [x] A Constraint Snapshot maps visible variables to symbols or concrete values.
- [x] The panel shows ranges against variable names where a mapping exists.
- [x] Symbols with no variable name remain visible in the panel.
- [x] The panel presents "known here" and "accumulated" separately.
- [x] The accumulated path condition retains constraints on symbols the analyzer has dropped as dead.
- [x] A Clang lit test proves that a constraint on a dead symbol still appears in the accumulated path condition.
- [x] The CodeChecker functional test covers the extended data, and the panel is checked in a real browser.


## Comments

### Plist contract additions (still `version` 1)

Purely additive, so `version` stays 1.
Each `steps` dict now also has:

```
variables: array of dict, sorted by name
  name: string, the variable name, e.g. a
  value: string
  kind: string, one of
    symbol: value is the symbol's dump, equal to a `symbol` in symbol_ranges/path_condition
    integer: value is a decimal integer, e.g. 0
    address: value is the pointed-to region's dump, e.g. &x
path_condition: array of dict, same shape as symbol_ranges, sorted by symbol
  symbol, range: as in symbol_ranges
```

- `symbol_ranges` is what the analyzer held at this step ("Known here"); `path_condition` is every constraint collected from the start of the path up to this step, and keeps symbols the analyzer dropped as dead ("accumulated").
- A step's `variables` are the current stack frame's locals and parameters that have a value, plus globals the function names. Values neither a symbol nor a concrete value (struct lazy values, unknown) are omitted.
- CodeChecker needed no parser change: the parser and `convert()` already copy unknown step keys through, and `ReportDetails.constraintTrace` returns them verbatim.

### How the accumulated path condition is built

- Same rule as `Z3CrosscheckVisitor`: later range replaces earlier on a symbol, and a symbol keeps its last range once it dies. The visitor gets that by walking backwards with first-seen-wins and overwriting at the end node; `PathDiagnosticBuilder` walks forward from the root because a step's condition depends on what came before it. Both use the extracted `mergeConstraintMaps` (`RangedConstraintManager.h`).
- Ticket 05: the per-node `ConstraintMap` (keyed by `SymbolRef`) is in `PathDiagnosticBuilder::PathHistory`, so an SMT-LIB string per step can be built there with `SMTConv::getRangeExpr` beside `renderConstraints`.
- `path_condition` uses every equivalence-class member's range (`getConstraintMapOfClassMembers`), not just the representative the crosscheck uses (`getConstraintMap`), so a named variable in a class still has its range. The extra entries are implied facts and can't change satisfiability beyond what the range manager already knows. Same as `symbol_ranges`.

### Traps for later tickets

- `State->getSVal` of a variable with no binding is not "no value": it returns the initial symbol for a parameter (and a new unconstrained one for an inlined parameter, which is why inlined and local variables are read from direct store bindings only). A top-frame parameter written and then dropped as dead would read back its stale initial symbol; `PathDiagnosticBuilder::FirstParameterWrite` excludes it.
- A variable shows no range at a late step (`a` above) while its symbol is still mapped: the name resolves, the analyzer simply no longer held a range for it there. The panel labels this "no known range" rather than hiding the variable; the accumulated section shows the constraint.
- `Calling` and `Entered call` events share the snapshot of the CallEnter node, so their variables are the caller's. The callee's parameters appear from the first event inside the call.
- `clang --analyze` (the dev loop fixture) enables `deadcode.DeadStores`, whose path-insensitive reports have no trace, unlike `%clang_analyze_cc1 -analyzer-checker=core`.
- lit CHECK lines match substrings: `VARS` lines end in `{{$}}` deliberately, otherwise an extra variable on a line passes unnoticed. That happened during this ticket.

### report_viewer_api failure

`test_get_run_results_checker_id_and_file_path` expects `core.StackAddressEscape` at lines 15 and 25 (the closing braces) and `unix.Malloc` at `new_delete.cpp:31` with its hash, from `web/tests/projects/cpp/project_info.json`.
The test isn't stale: `.github/workflows/install-deps.sh` pins CI to Clang 14, and running Homebrew `llvm@14` directly over the two files gives exactly those lines and report hashes (`a785826f`, `d8284a47`, `c2132f78`); Clang 24 gives 14, 24 and different hashes for all three.
Homebrew Clang 14.0.6 reports 15 and 25; Apple 21, Homebrew 22, 23 and the Colorful Day 24 report 14 and 24 (the StackAddressEscape checker moved its report to the assignment somewhere after 14).
A full suite run with `llvm@14` on PATH did not reach this comparison on macOS (49 failures, `clang++: error: no input files` from the test project's build), so the suite as a whole is not verified under Clang 14.
Left unchanged, because editing the expected lines would break upstream CI.

### Test results (2026-11-10)

- `dev-loop.sh lit`: 2/2. `clang/test/Analysis`: 1261 of 1262 not failing, the one failure being the user's untracked `bstring-UninitRead-partial-init.c` (known from ticket 02). `func-mapping-test.cpp` passes again after `dev-loop.sh clang`.
- `dev-loop.sh functest` (`constraint_trace`): 5 passed.
- `store`: 7 passed. `report_viewer_api`: 66 passed, 1 failed (the Clang 14 expectations above).
- report-converter unit: 136 passed, and the PVS test no longer changes tracked files.
- `pycodestyle`/`pylint` on touched Python, `eslint` on the panel, clang-format on touched C++: clean.

### Verification

Screens in `/Users/efulop/colorful-day-env/screens/`: `03-panel-1400-step2.png` (ranges against names), `03-panel-1400-last-step.png` and `03-panel-1100-last-step.png` (dead symbols marked dropped in the accumulated section only), `03-panel-1400-unnamed-symbol.png` and `03-panel-1100-unnamed-symbol.png` (raw symbol with no variable in Other symbols), `03-panel-900-last-step.png` (narrowest checked).
