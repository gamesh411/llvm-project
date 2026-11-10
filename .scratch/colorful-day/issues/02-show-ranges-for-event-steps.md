# 02: Show ranges for event steps, end to end

**What to build:** With the new analyzer config option enabled through CodeChecker's existing passthrough, a report reader turns on the debug view, clicks an event Path Step, and sees that step's symbol ranges in a side panel.
This is the tracer bullet through both repositories, from Clang's plist output to the web UI.

**Blocked by:** 01

**Status:** ready-for-agent

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
- Toolbar layout: at a 1400 wide window the toolbar has no free space, so the toggle is a 16px icon button, the Blame column lost its left padding, and the row is `flex-nowrap` while no side panel is open. With a panel open it wraps, like with Comments open.

### Verification

Screens in `/Users/efulop/colorful-day-env/screens/`: `02-off-state-1400.png` (toggle off, compare with `01-two-path-report.png`), `02-panel-open.png`, `02-panel-empty.png` (dead-symbol step), `02-no-data-tooltip.png`.
The file-path header showing `(None)` in the 02 shots differs from 01 because `two-path.c` is committed now and the unconfigured upstream branch is shown; it is unrelated to this ticket.
