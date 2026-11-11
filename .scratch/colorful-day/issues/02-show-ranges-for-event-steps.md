# 02: Show ranges for event steps, end to end

**What to build:** With the new analyzer config option enabled through CodeChecker's existing passthrough, a report reader turns on the debug view, clicks an event Path Step, and sees that step's symbol ranges in a side panel.
This is the tracer bullet through both repositories, from Clang's plist output to the web UI.

**Blocked by:** 01

**Status:** resolved

- [x] Clang's analyzer config option is off by default, and plist output is unchanged when it is off.
- [x] With the option on, every event Path Step in the plist carries a Constraint Snapshot with symbol ranges.
- [x] CodeChecker's parser, report model and storage carry the data through the existing report path data blob with no database migration.
- [x] The report details API exposes the data through an optional field, and the new blob item type is not returned as extended report data.
- [x] A toggle beside "Show arrows" is off by default and leaves the report page visually unchanged while off.
- [x] With the toggle on, clicking an event Path Step opens a side panel showing that step's ranges.
- [x] On a report with no constraint data, the toggle is disabled and explains why.
- [x] A Clang lit test covers the plist output, and a CodeChecker functional test stores a Clang-generated fixture plist and reads it back through the API, including the no-data case.
- [x] The behavior is checked in a real browser on the two-path example.

## Comments

### Plist contract (per-diagnostic key `constraint_trace`)

Emitted by Clang only when `-analyzer-config emit-constraint-snapshots=true` is set, and only for path-sensitive reports.
CodeChecker enables it through `--analyzer-config clangsa:emit-constraint-snapshots=true`.
Schema (the key sits next to `path` in the diagnostic dict):

```
constraint_trace: dict
  version: integer, currently 1. Bump on any change that isn't purely additive.
  steps: array, one dict per Path Step that has a Constraint Snapshot
    path_index: integer, index of this Path Step in the diagnostic's `path` array
    symbol_ranges: array of dict
      symbol: string, the analyzer's dump of the symbol, e.g. reg_$0<int a>
      range: string, the range manager's dump, e.g. { [0, 0] }
```

`path_index` counts every element Clang writes to `path` (event, control, pop-up), so a step can address control pieces too.
Consumers must ignore `steps` keys and top-level keys they don't know.
Later tickets add per-step keys beside `symbol_ranges` and keep this shape:

- 03: `variables` (visible name to symbol or concrete value), `path_condition` (accumulated constraints keeping dead symbols).
- 04: control-flow pieces get steps too; `path_index` already points to them.
- 05 and on: an SMT-LIB string per step or per trace.

### CodeChecker contract

The report parser turns `path_index` into the event's position among `bug_path_events` and stores the trace as `{"version": 1, "steps": [{"kind": "event", "index": N, "symbol_ranges": [...]}]}`, keeping any other step keys.
`kind` and `index` are what the UI uses to find a step's snapshot.
Storage is one `ReportPathData.Item` of type `constraint_trace` with the JSON in `msg`; a `report_server` branch keeps it out of `extendedData`, and `ReportDetails.constraintTrace` (API 6.75, optional string) returns it verbatim.

Ticket 04: parser and `plist.py convert()` map events only.
Control steps need their own branch in both (see below), and index control steps by `executionPath` position (the parser merges A->B, B->C into A, B, C, so the mapping is by the edge's end).

### Traps later tickets need

- `CodeChecker store` rewrites every plist through `report_file.create` before upload (see `store.py`), which goes through the parser's `convert()`. Any new report data must be written back in `convert()` or it silently disappears on store. `convert()` also places all control points before all events, which is why it recomputes `path_index`.
- `CodeChecker parse` output doesn't carry the trace (`Report.to_json` left alone, per scope).
- A snapshot only lists symbols still alive at that node, so late Path Steps often show no ranges (demo steps 3 and 4 show the empty state). That is expected and is why ticket 03's accumulated path condition exists.
- Clang's `-analyzer-config display-ctu-progress`/`analyzer-note-analysis-entry-points` debug events and `notes-as-events` conversions have no node and no snapshot; their `path` entries simply have no step.
- Fixture regeneration, `lit` and functional test runs are dev-loop subcommands: `dev-loop.sh fixture`, `lit`, `functest`. `fixture` writes `web/tests/projects/constraint_trace/{with_snapshots,no_snapshots}/` in the CodeChecker repo, with `$FILE_PATH$` for the test to rewrite. `functest` goes through `make test_web_feature`, which clears the test workspace and stops the global test server; a leftover server from a direct pytest run fails at `addProduct`.
- `llvm-lit` needs `llvm-config`, added to `dev-loop.sh clang`. `split-file` and `clang-extdef-mapping` are needed only if you run all of `clang/test/Analysis`.
- The dev requirements file pins `cryptography~=41`, which breaks the server's `joserfc`; `dev-loop.sh env` installs the test tools individually for that reason.
- Toolbar layout: at a 1400 wide window the toolbar has no free space. "Show constraints" is a checkbox stacked under "Show arrows" in one column, with the labels at 14px and an 18px checkbox, which is what makes `Comments` fit on the row again (the row has about 9px to spare at 1400; at 1100 it wraps as it always did). The side panel is a column beside the editor only, below the file header, so opening it does not touch the toolbar or the header.
- `Report.vue` draws arrows from CodeMirror's viewport-changed handler, which sees the marks only if the viewport changes after they are added. On first load it did not, so arrows were missing with "Show arrows" checked (not related to this ticket). `drawBugPath` now connects them itself after adding the marks.
- The header showed `(None)` because the client stored `str(tracking_branch())` for a branch without upstream. It now falls back to the commit hash, as for a detached head. Blame lives per file content hash on the server, so a content already stored with blame keeps its old `None` until its `file_contents.blame_info` is cleared.
- The long file path used to collapse to `...` beside the copy button; the path column is a flex box now so the ellipsis clips the left end of the path.
- `dev-loop.sh web` rsyncs the rebuilt dist into the package's `www`, which is a copy, not a symlink. Without that the server keeps serving the old UI.

### Test baseline

At 2026-11-10, same counts at `codechecker@a343881a2` (throwaway worktree) and at the ticket head, with identical failing test lists, so ticket 02 broke nothing:

| suite | env as first run | with `dev-loop.sh webtests` env |
| --- | --- | --- |
| `store` | 5 pass, 2 fail | 7 pass |
| `report_viewer_api` | 18 pass, 49 fail | 66 pass, 1 fail |

- Cause of the store failures: no `clang-tidy` on PATH (`test_same_headers`, `test_store_stats` analyse with clang-tidy). Homebrew's is `/opt/homebrew/opt/llvm/bin/clang-tidy`.
- Cause of `clang++: error: no input files` and the 0 stored reports: macOS make 3.81 on the test projects' Makefiles. GNU make from `/opt/homebrew/opt/make/libexec/gnubin` fixes it. `dev-loop.sh functest` and `webtests` put both on PATH.
- The one remaining failure, `report_viewer_api/test_get_run_results.py::test_get_run_results_checker_id_and_file_path`, expects `unix.Malloc` at `new_delete.cpp:31` and two `core.StackAddressEscape` at lines 15 and 25 of `stack_address_escape.cpp` with fixed report hashes. This Clang (24) reports those at lines 14 and 24, so the fixtures predate it. Not fixed: the expectations belong to the project fixtures, not to this work.
- `dev-loop.sh baseline [rev]` reproduces the comparison in a worktree under `$CD_ENV`.
- report-converter unit "9 errors" was the missing `REPO_ROOT`/`LAYOUT_DIR` env; `make -C tools/report-converter test_unit` gives 136 passed.
- `pylint` on `report_server.py`: 10.00/10.
- Clang `clang/test/Analysis`: after `dev-loop.sh clang` builds the ssaf tools, `Analysis/Scalable` is 111/111 and the whole directory 1260 of 1262. `func-mapping-test.cpp` failed only because `clang-extdef-mapping` was built after `clang` (AST files carry the build revision); it passes once `clang` is rebuilt. `bstring-UninitRead-partial-init.c` is the user's untracked file; its RUN line enables `alpha.unix.cstring`, but the checker is `unix.cstring.UninitializedRead` now (as in `bstring_UninitRead.c`), and the test passes with that checker name. The file was left alone.

### Verification

Screens in `/Users/efulop/colorful-day-env/screens/`, reworked: `02b-off-1400.png` (toggle off, compare with `01-two-path-report.png`; arrows drawn on first load, header shows the commit hash and a readable path), `02b-panel-1400.png`, `02b-panel-1100.png` (narrower, toolbar wraps as it always did), `02b-no-data.png` (disabled checkbox with its explanation). `02b-before-1400.png` is the old build showing `(None)`, the elided path and no arrows. The older `02-*.png` shots show the rejected layout.
