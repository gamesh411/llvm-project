# Handoff: the `defects` run on another machine

This folder carries the example reports of the Colorful Day run `defects`, and what it takes to see them, or to make them again, on a machine that never ran it.
The run is 109 reports: 106 from 11 LLVM and Clang source files and 3 from tmux `grid.c`.
Two of them are the ones the last UI work was checked on: `APInt.cpp:1363` (`core.BitwiseShift`) and tmux `grid.c:1073` (`core.NullDereference`).

## What is here

- `example-reports.tar.gz`: the two CodeChecker report directories of the run, `defects` (11 plists) and `tmux-grid` (1 plist), each with its `metadata.json` and compile commands. 25 MB unpacked.
- `cdb-llvm.json`: the compile commands of the 11 LLVM and Clang files.
- `cdb-tmux-grid.json`: the compile command of tmux `grid.c`.
- `handoff.sh`: `view` stores the example reports, `rerun` analyzes the same files again and stores the result.

The reports and the compile commands name the paths of the machine that made them, under `/Users/efulop`.
`handoff.sh` rewrites them to this machine's paths in a copy under `$CD_ENV/handoff`, and leaves this folder as it is.

## Revisions

| What | Where | Revision |
| --- | --- | --- |
| Clang and this folder | `gamesh411/llvm-project`, branch `colorful-day` | the commit that added this folder |
| CodeChecker | `gamesh411/codechecker`, branch `colorful-day` | `a15e1e75e` |
| tmux | `https://github.com/tmux/tmux` | `549c35b06165f6ae023115eb76f83f2cbf945395` |

The reports were made on 2026-11-13 at 05:02, before the three `[analyzer]` commits of that morning were committed, by a Clang built from that working tree.
The analyzed LLVM sources are those of this checkout, so the line numbers of the reports match it.

The machine was an Apple silicon Mac: macOS 26.5.1, Xcode 26.6, Homebrew Z3 5.4.0, libevent 2.1.13_1, ncurses 6.6, Python 3.13, Node 24.12.0, Docker 29.5.2.

## Paths

`handoff.sh` and `../dev-loop.sh` read the same variables, and each has a default:

| Variable | Default | What |
| --- | --- | --- |
| `LLVM` | the checkout this folder is in (`dev-loop.sh`: `/Users/efulop/llvm-project`) | llvm-project |
| `CC_REPO` | `$HOME/codechecker` | CodeChecker checkout |
| `CD_ENV` | `$HOME/colorful-day-env` | venv, server workspace, logs |
| `CLANG_BUILD` | `$LLVM/build-colorful` | the Colorful Day Clang |
| `NDEBUG_BUILD` | `$CD_ENV/llvm-scale/build` | LLVM build without assertions, for `rerun` |
| `TMUX_SRC` | `$CD_ENV/projects/tmux` | tmux checkout |
| `CD_PORT` | `8002` | server port |
| `RUN_NAME` | `defects` | name of the stored run |

`dev-loop.sh` has the old machine's paths as its defaults, so on another machine export `LLVM`, `CC_REPO` and `CD_ENV` before using it.
It also reads `NODE_BIN` (default `$HOME/.nvm/versions/node/v24.12.0/bin`) and `PYTHON` (default `/opt/homebrew/bin/python3.13`).

## 1. CodeChecker and its server

Needed for both `view` and `rerun`.
Docker has to be running, for the Thrift stubs.

```sh
git clone -b colorful-day git@github.com:gamesh411/llvm-project.git
git clone -b colorful-day git@github.com:gamesh411/codechecker.git
export LLVM=$PWD/llvm-project CC_REPO=$PWD/codechecker CD_ENV=$HOME/colorful-day-env
L=$LLVM/.scratch/colorful-day/dev-loop.sh
$L env && $L thrift && $L web && $L package && $L server
```

The What-If check and "Show an example" run Z3 on the server, through the `z3-solver` package of `web/requirements.txt`, which `env` installs.

## 2. See the example reports: `handoff.sh view`

```sh
git clone https://github.com/tmux/tmux "$CD_ENV/projects/tmux"
git -C "$CD_ENV/projects/tmux" checkout 549c35b06165f6ae023115eb76f83f2cbf945395
$LLVM/.scratch/colorful-day/handoff/handoff.sh view
```

CodeChecker stores a report only when every source file it names is on the machine, and leaves it out without failing otherwise.
So `view` first lists every file the reports name that is missing here, with the plists that name it, and stops.
The reports name four kinds of files:

- LLVM and Clang sources, which the checkout has.
- tmux `grid.c`, from the clone above.
- libc++ headers of the Xcode SDK, under `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk`, named by six of the plists.
  A Mac with Xcode has them, and their line numbers match only for the same SDK.
  On Linux those reports cannot be stored as they are, so use `rerun` there.
- One generated header, `tools/clang/include/clang/AST/DeclNodes.inc` in `NDEBUG_BUILD`.
  Configure that build as in step 3 and run `ninja -C "$NDEBUG_BUILD" ClangDeclNodes`.

`view` then stores both directories as one run and prints its link.
With "Show constraints" on, the two reports above are at `APInt.cpp` line 1363, step 8, and `grid.c` line 1073.

This was checked on 2026-11-13 by storing the archive under other paths on the machine that made it, with copies of the named files: 109 reports stored, and the constraint panel of the `grid.c` report showed its rows.
It was not run on a second machine.

## 3. Make the reports again: `handoff.sh rerun`

This needs the Colorful Day Clang, an LLVM build without assertions for the compile commands, and a configured tmux.

The Clang, with Z3, about 40 minutes cold:

```sh
brew install z3 ninja cmake
cmake -S "$LLVM/llvm" -B "$LLVM/build-colorful" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD=host \
  -DLLVM_ENABLE_ASSERTIONS=ON -DLLVM_ENABLE_Z3_SOLVER=ON \
  -DLLVM_Z3_INSTALL_DIR=/opt/homebrew
$L clang
```

The LLVM build that the 11 files are analyzed in.
Its compile commands define `NDEBUG`, which changes what the analyzer reports, so `build-colorful` cannot stand in for it.

```sh
cmake -S "$LLVM/llvm" -B "$CD_ENV/llvm-scale/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS=clang "-DLLVM_TARGETS_TO_BUILD=AArch64;X86" \
  -DLLVM_ENABLE_ASSERTIONS=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++
ninja -C "$CD_ENV/llvm-scale/build"
```

The analysis needs only the generated headers of that build, but which targets make all of them was not worked out, so the line above builds everything.

tmux, configured as it was:

```sh
brew install libevent ncurses autoconf automake pkg-config
cd "$CD_ENV/projects/tmux" && sh autogen.sh && ./configure --disable-utf8proc
```

Then:

```sh
$LLVM/.scratch/colorful-day/handoff/handoff.sh rerun
```

It rewrites the two compile command files to this machine's paths, analyzes with `--analyzers clangsa -j8 --z3-refutation on --analyzer-config clangsa:emit-constraint-snapshots=true`, as the run was, and stores the result as `defects-rerun`.
On the old machine the LLVM part took 186 seconds and the tmux part 5.

What the compile commands still assume after the rewrite:

- `cdb-llvm.json` has `-isysroot` of the Xcode SDK and `-isystem /opt/homebrew/include`.
- `cdb-tmux-grid.json` has the Homebrew Cellar paths of libevent 2.1.13_1 and ncurses 6.6, and `/usr/bin/gcc` as the compiler.

Where those differ, take the entries of the 11 files from `$NDEBUG_BUILD/compile_commands.json`, and log tmux again with `CodeChecker log -b "make grid.o" -o cdb-tmux-grid.json`.

`rerun` was not run for this handoff.
Its analyze and store commands are those of the original run, from `df/analyze-store.sh` on the old machine, and the configure lines are read from the two builds' `CMakeCache.txt` and tmux's `config.log`.
Report hashes should match the example reports' when the sources and the SDK do.
