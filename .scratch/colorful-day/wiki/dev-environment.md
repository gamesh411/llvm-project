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
