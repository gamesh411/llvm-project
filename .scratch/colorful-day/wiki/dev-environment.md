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
