# Dev environment

Related: [worker rules](worker-rules.md).

## 2026-11-10: initial state and decisions

On 2026-11-10 the only LLVM build directory was `build-bolt-macos`, and it contained no `bin/clang`, so ticket 01 was assigned a new Z3-enabled Release build at `build-colorful`.

On 2026-11-10 the lead placed the ticket venv and server workspace under `/Users/efulop/colorful-day-env/` so that the existing `/Users/efulop/venv`, `.venv-cc` and `~/.codechecker` stay untouched.
The server uses an explicit workspace and port 8002 unless that port is taken.

On 2026-11-10 ticket 01 was also asked for `.scratch/colorful-day/dev-loop.sh`, so that later workers run the loop by command and don't rediscover it.
Whether it exists at a given commit has to be checked in that commit.

## 2026-11-10: ticket 01 outcome

As of `llvm-project@da4604b880b8` and `codechecker@a343881a2`, `dev-loop.sh` offers `env`, `clang`, `thrift`, `web`, `package`, `analyze`, `server`, `store`, `stop`, `status` and `all`.
Traps found are listed in the Comments of `../issues/01-codechecker-dev-loop.md`.

On 2026-11-10 the lead accepted ticket 01 after viewing `/Users/efulop/colorful-day-env/screens/01-two-path-report.png`, which shows one report with Bug Path `a == 0`, `b != 0`, and after checking the `Pool` callers against the macOS wrapper added in `codechecker@a343881a2`.

The claim above that all generated state lives under `/Users/efulop/colorful-day-env/` is superseded in one respect: the CodeChecker Makefiles hardcode `tools/*/build`, so the dev package stays at the gitignored `/Users/efulop/codechecker/build/CodeChecker`.

## 2026-11-10: wiki lint corrections

The list of `dev-loop.sh` subcommands in the ticket 01 outcome above is superseded: as of `llvm-project@b890c79d9a57`, the script also offers `fixture`, `lit` and `functest`.

On 2026-11-11 a wiki lint found that list incomplete as well: as of `llvm-project@2872a9cbe8f3`, `dev-loop.sh` also offers `webtests`, `baseline` and `demo`.

The "all generated state" claim that the ticket 01 outcome calls superseded is in the Comments of `../issues/01-codechecker-dev-loop.md`, not on this page.

## 2026-11-10: test baseline after ticket 02

On 2026-11-10 the ticket 02 rework worker reported identical failing lists at `codechecker@a343881a2` and at the rework head for `store` and `report_viewer_api`, so ticket 02 caused no regression there.
The worker traced those failures to macOS make 3.81 and a missing clang-tidy on `PATH`, and as of `llvm-project@16929a93154e` `dev-loop.sh` `functest` and `webtests` set up both.
With that setup the worker reported `store` 7/7 and `report_viewer_api` 66/67, the remaining failure being expected line numbers 15 and 25 against reported 14 and 24.

On 2026-11-10 the lead found that running the report-converter unit tests rewrites the tracked files `tools/report-converter/tests/unit/analyzers/pvs_studio_output_test_files/sample.json` and `sample.plist`, and restored them.

## 2026-11-10: remaining report_viewer_api failure

On 2026-11-10 the ticket 03 worker reported that `test_get_run_results_checker_id_and_file_path` encodes Clang 14 behavior, which `.github/workflows/install-deps.sh` pins for CI, so the one failure under newer Clangs (66/67) is a version mismatch and the expectations were left unchanged at `codechecker@adfc87b94`.
The worker confirmed the expected lines and hashes by running Homebrew `llvm@14` directly on the two files, and did not get the whole suite to run under Clang 14 on macOS.
This updates the earlier "stale" description in the test baseline entry above.

## 2026-11-10: possible store flake

On 2026-11-10 the ticket 04 worker saw one `store` run fail `test_same_headers` and `test_store_stats` with 3 clang-tidy reports instead of 6, then 7/7 on two reruns, with the failing log lost. Unexplained as of `codechecker@41f307f73`.

## 2026-11-10: server stop hangs

On 2026-11-10 the ticket 06 worker reported that, as of `llvm-project@0507cd96feb8`, `dev-loop.sh stop` leaves the server hanging in shutdown while a browser is connected, and killed it by port instead. The lead assigned a proper fix to the ticket 07 worker.

## 2026-11-10: server stop fixed

As of `codechecker@6325f9164`, the shutdown hang reported after ticket 06 is fixed in `server.py`. API workers sat in `accept()` while SIGINT landed on Z3's timer thread. `dev-loop.sh stop` now waits for shutdown and fails loudly, which supersedes the kill-by-port practice noted above.

## 2026-11-11: functest poisoning and trace path trimming

As of `codechecker@333e8467d`, a failing `setup_class` in `constraint_trace` used to leave its product on the global test server, because pytest skips `teardown_class` after a failed setup and runs `setup_class` again for the next test.
Every later test then failed with "Failed to add the product to the test server!" ("product endpoint is already configured"), which hid the first real error.
The setup now removes the product and workspace itself before re-raising, so each test shows the real error.
The trigger seen in the reproduction was a sporadic `CodeChecker store` failure ("No such file or directory" on the store zip in `<report dir>/tmp*-store/`), roughly one run in five, cause not found.
`dev-loop.sh functest` also stops a leftover global test server first: the Makefile deletes the workspace and its `serverport` file, so an orphan could never be stopped afterwards.

## 2026-11-11: store zip failure explained and fixed

As of `codechecker@63ec865ce`, the sporadic `CodeChecker store` failure noted in the functest poisoning entry above is fixed, and its cause is known.
`multiprocess` forks on macOS, so pool workers inherit the SIGTERM handler of `codechecker_common/cli.py`, which raises SystemExit.
The `Pool` wrapper added in `codechecker@a343881a2` kept the base `__exit__`, which terminates the workers.
A SIGTERM that lands while a worker runs its atexit hooks raises past `os._exit`, so the forked child unwinds into the parent's copied stack and runs the `finally` of `store.main`, deleting `<report dir>/tmp*-store/` while the parent still writes the zip.
The wrapper's `__exit__` now closes and joins, as `ProcessPoolExecutor` does on Linux.
Before `a343881a2`, `store` on macOS failed every time with a `TypeError` on `Pool(max_workers=...)`, so the race was latent there in the one `with Pool()` that store reached only after parsing.
Measured with detached stores of the `with_snapshots` fixture, 4 in parallel: 8 failures in 1200 before, 0 in 1200 after; `functest` 1 failure in 20 before, 0 in 20 after.
`web/client/tests/unit/test_pool.py` fails deterministically on the old wrapper by slowing worker exit.
The ticket 04 `store` suite failure (3 clang-tidy reports instead of 6) was not reproduced and is not shown to share this cause.
