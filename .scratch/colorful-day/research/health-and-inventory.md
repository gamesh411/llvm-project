# Colorful Day: health check and inventory

Date: 2026-11-12.
Measured at `llvm-project@6dc2604108f7` (branch `colorful-day`, 53 commits over `upstream/main` at `b216f903b601`) and `codechecker@b7b6d1c72`, then `codechecker@978ea7699` after the one fix below.
Related: [wiki index](../wiki/index.md), [execution plan](../wiki/execution-plan.md), [dev environment](../wiki/dev-environment.md).

## 1. Health

The server on port 8002 was already running when the check began, was not started or stopped by this check, and is still up.

| Suite | Command | Result |
|---|---|---|
| Colorful Day lit | `dev-loop.sh lit` | 7 passed, 1 unsupported (`constraint-snapshots-no-z3.c`, Clang has Z3) |
| Whole `clang/test/Analysis` | `llvm-lit -s clang/test/Analysis` | 1247 passed, 5 expectedly failed, 14 unsupported, 2 failed (see below) |
| CodeChecker functional | `dev-loop.sh functest` | `constraint_trace` 33 passed |
| `store` functional | `dev-loop.sh webtests` | 8 passed |
| `report_viewer_api` functional | `dev-loop.sh webtests` | 66 passed, 1 failed (the known Clang 14 line-number test) |
| report-converter unit | `make -C tools/report-converter test_unit` | 150 passed |
| web server unit | `make -C web test_unit` | 119 passed |
| web client unit | `make -C web test_unit` | 5 passed |
| web jest | `jest` in `web/server/vue-cli` | 17 passed, 4 suites |
| eslint | `eslint --ext .js,.vue src` | clean |
| pylint | on the 25 Python files the branch added or modified | 9.99/10, 9 messages, 1 introduced by the branch (fixed) |
| pycodestyle | same files | clean |
| `git clang-format --diff b216f903b601` | against the merge base with `main` (`origin/main` and `upstream/main` give the same base) | "did not modify any files" |
| analyzer unit | `make -C analyzer test_unit` | 12 failed, 8 errors, 121 passed; not baselined, see below |

Failures in `clang/test/Analysis`:

- `bstring-UninitRead-partial-init.c` is the user's untracked file, as already noted in the ticket 03 Comments, so it is not part of the branch.
- `func-mapping-test.cpp` failed with "clang-extdef-mapping: unable to load precompiled file" because `build-colorful/bin/clang-extdef-mapping` was stale against `bin/clang` (the ticket 03 Comments record the same).
  `ninja clang-extdef-mapping` fixed it and the test passes, so nothing to commit.
  `dev-loop.sh lit` does not build that tool, which is why the trap recurs after a Clang rebuild.

Known baseline held: `report_viewer_api` fails only `test_get_run_results_checker_id_and_file_path`, as in [dev environment](../wiki/dev-environment.md).
`store` is now 8 tests, up from 7 in the wiki, because the store pass added one.
The "3 clang-tidy reports instead of 6" flake did not appear in this run.

Lint triage:

- pylint W1203 at `web/client/codechecker_client/cli/store.py:456` was introduced by `codechecker@94ff2f90b` (the store batching change).
  It is fixed in `codechecker@978ea7699`.
- The other eight pylint messages (W1203 in five other places of `store.py`, W1201 in `mass_store_run.py:1595`, W0706 in `report_server.py:1780`, C0103 in `test_plist_parser.py:106`) sit on lines whose `git blame` commits are ancestors of `bae448521`, the merge base, so they are upstream's and left alone.
- The analyzer unit failures (`test_option_parser`, `test_log_parser`, `test_env_var`, `test_checker_handling` errors) are in code the branch does not touch (`git diff bae448521..HEAD -- analyzer` is empty).
  They were not run at the merge base, so "unrelated" rests on that diff only.
  They are not caused by test pollution of tracked files: `git status` shows no tracked changes in either repository after all runs.

`dev-loop.sh demo` from a clean server: works.
It was run with an isolated environment (`CD_ENV` holding only `logs/` and symlinks to the real `venv` and `projects`, `CD_PORT=8012`) because the command stops the server named in `$CD_ENV/server.pid` and deletes `demo-workspace`.
It finished in 59 s, stored the three runs and printed report links 1 (two-path), 21 (tmux `grid.c:1073`) and 33 (contexts).
`demo/README.md` still gives the tmux report as `report-id=5`, so the ID in the README is stale against a clean demo (see inventory item 28).
The isolated server was stopped, and the user's server was not touched.

Docs for the analyzer option and the CodeChecker feature:

- Analyzer option: only the `ANALYZER_OPTION` help string for `emit-constraint-snapshots` in `clang/include/clang/StaticAnalyzer/Core/AnalyzerOptions.def`, which was updated for CFGs and nodes in `llvm-project@2872a9cbe8f3`.
  `git diff b216f903b601..HEAD -- clang/docs` is empty, so there is no page in `clang/docs/analyzer`.
- CodeChecker feature: none.
  `git diff bae448521..HEAD -- '*.md'` is empty, and no file under `docs/` mentions `emit-constraint-snapshots`, "Show constraints" or the what-if API.
  The only prose is under `.scratch/colorful-day/` (spec, `trace-format-v2.md`, `demo/README.md`, the wiki).

Project files in the repositories: nothing uncommitted or untracked belongs to the project.
`llvm-project` has no modified tracked files, and its untracked files (`.scratch/threading-checker-refactor/`, `clang/tools/clang-rcu-analyzer/`, the `bstring` test and so on) are the user's.
`codechecker` has no modified tracked files, and its untracked files (`config/*.json`, `compile_commands.json`, `docs/issues/`, `.sandcastle/`, `infer-out/` and similar) date from July and are the user's.
This report is the only new project file and is meant to stay uncommitted.
Neither branch has a remote-tracking branch, so all 53 + 53 commits are local, as the spec requires.

## 2. Inventory

"Still true" was checked at the cited heads by reading code or running the command, unless it says "not verified".
Size is S (under an hour), M (a worker-session) or L (several sessions or a design change).

| # | Item | Source | Still true at HEAD? | Size | Decision? |
|---|---|---|---|---|---|
| 1 | No user docs for the analyzer option beyond its help string | `spec.md` user stories 2 and 3, no doc ticket | Yes, `clang/docs` untouched | S | No |
| 2 | No docs for the CodeChecker feature (toggle, what-if, `-analyzer-config` passthrough, API 6.79 notes) | same | Yes, no `.md` changes | S to M | No |
| 3 | Mitigation 7: lazy trace fetching (`getConstraintTrace` or per-step) | `perf-evaluation.md` Mitigations; `wiki/execution-plan.md` "trace format v2 accepted" | Yes, no such API in `report_server.thrift`; `cmd results --details` still ships traces | M | Yes: only worth it when a size need is measured, none is at 3.8 MB |
| 4 | Mitigation 8: gzip or raw-JSON transport | `perf-evaluation.md`; execution plan, same entry | Yes, no gzip in `server.py` | M | Yes, same reason |
| 5 | Mitigation 9: bounded pool and rate limit for What-If, worst case 8 s per API worker | `perf-evaluation.md` | Yes, no pool or limiter in `what_if.py` | M | Yes (policy: limit per user?) |
| 6 | Mitigation 11: size guard (cap, mark truncated, refuse What-If) | `perf-evaluation.md`; execution plan "CFG and store pass" says no remaining measured need | Yes, not implemented | S | Yes, safety net vs. none |
| 7 | Mitigation 13: deterministic symbol dumps (`LC`, `S` IDs) | `perf-evaluation.md` Non-determinism; execution plan "lane A" | Yes, NFC checks still normalize node and symbol IDs; not re-measured | M | Yes: touches analyzer dump format, upstream-only |
| 8 | Mitigation 10, remaining half: SMT-LIB only on demand (`--emit-smtlib` sub-option) | `perf-evaluation.md` | Yes, v2 stores SMT per-step deltas but always emits them; not re-measured | S in Clang, M for What-If reconstruction | Yes |
| 9 | Mitigation 2, 3, 4, 5, 6, 12, 14 and 1 | `perf-evaluation.md` | Done: see execution plan entries (lane A, lane B, v2, CFG pass); listed only for completeness | none | No |
| 10 | Both store peaks are Thrift's JSON codec moving the whole base64 zip (112 MB on LLVM); CodeChecker's own `massStoreRun` design | `wiki/execution-plan.md` "CFG and store pass accepted", "Left open" | Not verified (needs the LLVM run); code unchanged since | L | Yes: a Thrift API change |
| 11 | CFG rows scrolled out of view are not in the DOM, so Ctrl+F misses them | same entry | Yes, `ControlFlowGraphView.vue` renders `visibleBlocks` and `shownRows` | M | Yes (virtualization vs. find) |
| 12 | Multi-file tree labels show only the file name | `wiki/execution-plan.md` "wiki lint corrections"; `wiki/web-ui-decisions.md` second polish | Not verified; recorded as upstream behavior | S | Yes (leave as upstream?) |
| 13 | First click on the active report tree item only deactivates it (Vuetify toggle) | `wiki/web-ui-decisions.md` "polish pass accepted" | Not verified; recorded as upstream | S | Yes |
| 14 | At 900 px the What-If placeholder clips and the two checkboxes wrap under the toolbar | `wiki/web-ui-decisions.md` "second polish pass" | Not verified in a browser | S | No |
| 15 | Raw symbol dumps can break after "(", leaving "- (" at a line end | same | Not verified | S | No |
| 16 | CFG view shows full paths inside trace strings | same | Not verified | S | No |
| 17 | Report tree labels and 900 px clipping unchanged from upstream | same | Not verified | S | Yes (same as 12) |
| 18 | Integer ranges such as `[-2147483648, -1] [1, 2147483647]` not shortened, because the dump has no width | `issues/08-demo-on-a-real-report.md` Comments | Not verified in the panel; the cause is unchanged in Clang | M | Yes (needs width in the dump) |
| 19 | `derived_` pointer keeps its interval, since its dump carries no type | `issues/08-...` Comments | Not verified in the panel; same cause | M | Yes |
| 20 | Ticket 06 timeout checkbox intentionally unticked: no API-level test of the solver timeout; unit test only | `issues/06-full-what-if-input-and-unknown.md` "Lead decision" | Yes, `test_what_if.py` is still the only cover | S | Already decided (kept) |
| 21 | Spec's solver-mismatch concern stays open for nonlinear arithmetic and bit tricks | `spec.md` Further Notes (2026-11-11) | Yes, only `z3-refuted.c` exercises a Z3-only refutation | M | Yes: judgement on usability |
| 22 | Possible `store` flake: 3 clang-tidy reports instead of 6, never reproduced | `wiki/dev-environment.md` "possible store flake"; `issues/04`, `05` | Did not recur in this run (8/8); cause unknown | M | No |
| 23 | Report page `ReportDetail.vue` loads only on mount, so a router push to another `report-id` leaves the old report | `issues/06-...` Comments | Not verified; recorded as upstream | S | Yes |
| 24 | `:deep(...)` in `Report.vue`'s non-scoped `<style lang="scss">` is emitted literally, so those rules (`.cm-line:hover`, blame, search match) never apply | `issues/05-first-what-if-constraint-and-verdict.md` Comments | Yes, `:deep` still at lines 1689 to 1707 inside the non-scoped block starting at line 1630 | S | Yes (fix or leave as upstream) |
| 25 | A syntax error in a What-If Constraint still runs the Baseline Verdict | `perf-evaluation.md` Stage 5 | Not verified; `issues/06` Comments say it is by design ("a typo is always ...") | S | No |
| 26 | Blame for content already stored keeps its old `None` branch string until re-stored | `issues/02-show-ranges-for-event-steps.md` Comments | Not verified; the client fix at `blame_info.py:23` is present | S | No |
| 27 | Not measured: PostgreSQL, concurrent stores, slow networks, Firefox | `perf-evaluation.md` "What was measured" | Yes, nothing in the wiki says otherwise | M | No |
| 28 | `demo/README.md` gives tmux as `report-id=5`; a clean `dev-loop.sh demo` now makes it 21 | `.scratch/colorful-day/demo/README.md` lines 25 to 27; `dev-loop.sh` comment "report IDs of the first two stay" | Yes, measured today (1, 21, 33) | S | No |
| 29 | Analyzer unit suite fails (12 failed, 8 errors) in this environment | this check | Yes today; branch does not touch `analyzer/` | S to M | No |
| 30 | `dev-loop.sh lit` does not rebuild `clang-extdef-mapping`, so `func-mapping-test.cpp` fails after Clang rebuilds | `issues/03-...` Comments; this check | Yes | S | No |
| 31 | Branch is local only; nothing pushed, no upstream submission, no no-mistakes gate run | `spec.md` Repository handling and Out of Scope | Yes, no remote-tracking branch | L | Yes (the user's call) |
| 32 | Out of scope, unchanged: bug-level answers, injecting constraints into forward analysis, reachability queries, saving What-If, static HTML from `CodeChecker parse`, new CLI flag, full C parser, Z3 in the browser | `spec.md` Out of Scope | Yes, none exists (the grep of the Thrift API shows only `checkWhatIf`) | L each | Yes, if wanted |
| 33 | Web UI has only 17 jest tests (the trace reader); the spec required no committed UI tests | `spec.md` Testing Decisions | Yes | M | Yes |
| 34 | `emit-constraint-snapshots` help text: "not done" in ticket 10 | `issues/10-stretch-exploded-graph-view.md` Comments | No, fixed in `llvm-project@2872a9cbe8f3` (help mentions CFGs and nodes) | none | No |
| 35 | Z3 stopgap, thrift limit, PVS-Studio fixture rewrite, store zip race, server-stop hang, functest poisoning, `python-ldap`, slow step clicks, three polish defects | wiki "wiki lint corrections" entries | No, all recorded as fixed | none | No |

There are no `TODO`, `FIXME` or `XXX` markers in the added lines of either branch diff (`b216f903b601..HEAD` for `clang`, `bae448521..HEAD` for `codechecker`).

## 3. Cleanup state

- Tracked files: clean in both repositories after every test run.
- Commit made by this check: `codechecker@978ea7699` "store: lazy logging in the parse progress message", with no trailer, local only.
- Server on 8002: running before and after, untouched.
- The isolated demo server on 8012 was stopped, and its scratch directory is under the session scratchpad.
- Wiki and this file are not committed.
