# 01: CodeChecker dev loop on colorful-day

**What to build:** A developer can analyze the two-path example with the Colorful Day Clang build, store the report on a local CodeChecker server, and open it in a browser using the web UI built from the CodeChecker `colorful-day` branch.
The same loop proves that the Thrift API can be regenerated with the pinned Docker image.
This is prefactoring for every later ticket, and it records the exact commands so later tickets don't rediscover them.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [x] A Python environment for the `colorful-day` CodeChecker branch can run the analyzer, store and server commands.
- [x] The web UI builds from the branch and the running server serves that build.
- [x] The two-path example, analyzed with the Colorful Day Clang through `PATH`, appears as one report with one Bug Path in the browser.
- [x] Regenerating the Thrift API with the pinned Docker image succeeds, and the regenerated packages install and run.
- [x] The commands for this loop are written down in a Comments section on this ticket.

## Comments

Everything runs through `.scratch/colorful-day/dev-loop.sh`.
Subcommands: `env`, `clang`, `thrift`, `web`, `package`, `analyze`, `server`, `store`, `stop`, `status`, `all`.
Generated state lives in `/Users/efulop/colorful-day-env/` (venv, workspace, reports, logs, screens), except the CodeChecker dev package, see below.

Setup used here:

- Clang: `cmake -S llvm -B build-colorful -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD=host -DLLVM_ENABLE_ASSERTIONS=ON -DLLVM_ENABLE_Z3_SOLVER=ON -DLLVM_Z3_INSTALL_DIR=/opt/homebrew`, then `dev-loop.sh clang` (ninja clang FileCheck not count, about 40 minutes cold).
- Z3 check: `LLVM_ENABLE_Z3_SOLVER:BOOL=ON` in the cache, `otool -L bin/clang` lists libz3, and `clang --analyze -Xclang -analyzer-config -Xclang crosscheck-with-z3=true` runs.
- Python env: python3.13 venv from `analyzer/requirements.txt` and `web/requirements.txt` (the default python3 is 3.15, avoided for wheel availability).
- Thrift: `dev-loop.sh thrift` builds the image from `codechecker_api/Dockerfile` and runs `make thrift_stubs`. The output dirs are gitignored, so nothing to commit.
- Web: `dev-loop.sh web` runs `npm ci` and `npm run-script build` with node 24 in `web/server/vue-cli`, output `dist/` is gitignored.
- Package: `dev-loop.sh package` runs `make dev_package`, a package of symlinks into the checkout at `codechecker/build/CodeChecker`, so Python edits are live but a UI change needs `web` then `package`.
- Loop: `dev-loop.sh analyze` (Colorful Day Clang first on PATH, `--z3-refutation on`), `server` (port 8002, workspace `colorful-day-env/workspace`), `store` (run name `colorful-day-demo`).
- Report URL: `http://localhost:8002/Default/reports?run=colorful-day-demo`, then open the single report.
- Evidence: `/Users/efulop/colorful-day-env/screens/01-two-path-report.png` shows one report, Bug Path steps `a == 0`, `b != 0`, null stored, dereference.

Traps:

- The user's shell defines `node`/`npm` as lazy nvm functions that recurse forever non-interactively. The script unsets them and prepends a real node.
- `make dev_package` on macOS: `ln -s CodeChecker codechecker` on a case-insensitive filesystem replaces the copied binary with a self-link, and a second run fails copying onto symlinks. The script wipes `build/` first and restores the binary afterwards.
- The Makefiles hardcode `tools/*/build`, so `BUILD_DIR` cannot move into the env dir.
- web `check_dist` runs `npm install`, which rewrites `package-lock.json`. The script writes the `.build-commit` stamp and restores the lockfile.
- `CodeChecker parse` exits 2 when it finds defects, which is success here.
- The server crashed at startup on macOS (`Pool(max_workers=...)` with the `multiprocess` Pool). Fixed in the CodeChecker repo by giving the macOS Pool the ProcessPoolExecutor interface.
- The demo path depends on the analyzer's choice of path. A naive "p = &x; if (a == 0) p = 0; if (b != 0) p = 0" is reported along `a != 0, b != 0`, so `two-path.c` resets and re-assigns to force `a == 0, b != 0`.

