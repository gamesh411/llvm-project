#!/usr/bin/env bash
# Colorful Day dev loop: Clang build -> CodeChecker analyze -> store -> server -> browser.
# Re-runnable; every step fails loudly. All generated state lives under $CD_ENV.
# Usage: dev-loop.sh <env|thrift|web|package|clang|analyze|store|server|stop|status|all|fixture|lit|functest|webtests|baseline|demo> [args]
set -euo pipefail

LLVM=${LLVM:-/Users/efulop/llvm-project}
CC=${CC_REPO:-/Users/efulop/codechecker}
CD_ENV=${CD_ENV:-/Users/efulop/colorful-day-env}
BUILD=${CLANG_BUILD:-$LLVM/build-colorful}
PORT=${CD_PORT:-8002}
DEMO=${DEMO:-$LLVM/.scratch/colorful-day/demo/two-path.c}
RUN_NAME=${RUN_NAME:-colorful-day-demo}
NODE_BIN=${NODE_BIN:-$HOME/.nvm/versions/node/v24.12.0/bin}
PYTHON=${PYTHON:-/opt/homebrew/bin/python3.13}

VENV=$CD_ENV/venv
# The CodeChecker Makefiles hardcode tools/*/build, so BUILD_DIR cannot be
# redirected into $CD_ENV; the (gitignored) default $CC/build is used.
PKG=$CC/build/CodeChecker
WORKSPACE=$CD_ENV/workspace
DEMO_WORKSPACE=$CD_ENV/demo-workspace
REPORTS=$CD_ENV/reports
URL=http://localhost:$PORT/Default

die() { echo "dev-loop: $*" >&2; exit 1; }

# The user's shell defines `node`/`npm` as lazy nvm functions that break
# non-interactively; drop them and put a real node first on PATH.
use_node() {
  unset -f node npm npx 2>/dev/null || true
  [ -x "$NODE_BIN/node" ] || die "node not found in $NODE_BIN (set NODE_BIN)"
  export PATH=$NODE_BIN:$PATH
}

activate() {
  [ -f "$VENV/bin/activate" ] || die "venv missing, run: dev-loop.sh env"
  # shellcheck disable=SC1091
  . "$VENV/bin/activate"
}

# Colorful Day Clang first on PATH so CodeChecker picks it up.
use_clang() {
  [ -x "$BUILD/bin/clang" ] || die "no $BUILD/bin/clang, run: dev-loop.sh clang"
  export PATH=$BUILD/bin:$PATH
}

# CodeChecker's functional tests need GNU make (macOS make 3.81 breaks the test
# projects' Makefiles: "clang++: error: no input files") and a clang-tidy.
use_test_tools() {
  [ -x /opt/homebrew/opt/make/libexec/gnubin/make ] \
    || die "GNU make missing: brew install make"
  [ -x /opt/homebrew/opt/llvm/bin/clang-tidy ] \
    || die "clang-tidy missing: brew install llvm"
  export PATH=/opt/homebrew/opt/make/libexec/gnubin:$PATH:/opt/homebrew/opt/llvm/bin
}

cc_bin() { echo "$PKG/bin/CodeChecker"; }

cmd_env() {
  mkdir -p "$CD_ENV"/{logs,screens}
  [ -d "$VENV" ] || "$PYTHON" -m venv "$VENV"
  activate
  pip install -q -U pip
  pip install -q -r "$CC/analyzer/requirements.txt" -r "$CC/web/requirements.txt"
  # pytest and linters for `functest` and lint runs. Not the dev requirements
  # file: its cryptography~=41.0 pin is too old for joserfc in requirements.txt.
  pip install -q 'pytest<=7.3.1' 'pylint<3.3' 'pycodestyle<=2.12.0' 'cryptography>=45'
  # python-ldap for the server unit tests (test_ccldap.py imports it).
  pip install -q -r "$CC/web/requirements_py/auth/requirements.txt"
  python -c 'import lxml, sqlalchemy, thrift, ldap' && echo 'env ok'
}

# Clang plus the tools clang/test/Analysis needs: llvm-config for llvm-lit,
# Scalable/ssaf-*, func-mapping. A stale clang-extdef-mapping or clang fails
# func-mapping-test.cpp with "unable to load precompiled file" (the AST embeds
# the build revision), so `lit` builds them too.
build_lit_tools() {
  (cd "$BUILD" && ninja clang FileCheck not count llvm-config \
    clang-ssaf-analyzer clang-ssaf-format clang-ssaf-linker \
    clang-ssaf-src-edit-merge SSAFExamplePlugin SSAFTestTransformationPlugin \
    split-file clang-extdef-mapping yaml2obj)
}

cmd_clang() {
  [ -d "$BUILD" ] || die "configure $BUILD first (see ticket 01 comments)"
  build_lit_tools
  grep -E '^LLVM_ENABLE_Z3_SOLVER:BOOL=ON' "$BUILD/CMakeCache.txt" >/dev/null \
    || die "Z3 is not enabled in $BUILD/CMakeCache.txt"
  "$BUILD/bin/clang" --version
}

# Regenerate Python and JS stubs with the Docker image pinned by
# codechecker_api/Dockerfile. Output dirs are gitignored.
cmd_thrift() {
  docker info >/dev/null 2>&1 || die "docker daemon not running"
  (cd "$CC/codechecker_api" && make thrift_docker && make thrift_stubs)
  [ -d "$CC/codechecker_api/python" ] || die "thrift python stubs missing"
  [ -d "$CC/codechecker_api/js" ] || die "thrift js stubs missing"
}

# Web UI dist: web/server/vue-cli/dist (gitignored).
cmd_web() {
  use_node
  (cd "$CC/web/server/vue-cli" && npm ci --no-audit --no-fund && npm run-script build)
  # Same stamp web/Makefile writes; without it `package` throws the dist away.
  git -C "$CC" log -n 1 --pretty=format:%H web/server/vue-cli \
    >"$CC/web/server/vue-cli/dist/.build-commit"
  [ -f "$CC/web/server/vue-cli/dist/index.html" ] || die "web dist not built"
  # A dev package copies www (only lib dirs are symlinks), so a rebuilt UI
  # needs syncing into it.
  [ -d "$PKG/www" ] && rsync -a --delete "$CC/web/server/vue-cli/dist/" "$PKG/www/"
  return 0
}

# Dev package whose lib dirs are symlinks into the checkout, so Python edits
# are live. Rebuilds the Thrift stubs, so it needs docker.
cmd_package() {
  use_node
  activate
  # dev_package is not idempotent (cp onto its own symlinks), so start clean.
  rm -rf "$CC/build"
  make -C "$CC" dev_package >"$CD_ENV/logs/package.log" 2>&1 \
    || { tail -30 "$CD_ENV/logs/package.log" >&2; die "dev_package failed"; }
  # On case-insensitive APFS the Makefile's `ln -s CodeChecker codechecker`
  # replaces the copied binary with a symlink to itself. Restore the binary.
  rm -f "$PKG/bin/codechecker" "$PKG/bin/CodeChecker"
  cp "$CC/bin/CodeChecker" "$PKG/bin/CodeChecker"
  # web/Makefile check_dist runs `npm install`, which rewrites the lockfile.
  git -C "$CC" checkout -- web/server/vue-cli/package-lock.json
  [ -x "$(cc_bin)" ] || die "no $(cc_bin)"
  [ -f "$PKG/www/index.html" ] || die "package has no web UI under $PKG/www"
  "$(cc_bin)" analyzer-version >/dev/null && echo "package ok: $(cc_bin)"
}

cmd_analyze() {
  activate; use_clang
  rm -rf "$REPORTS"; mkdir -p "$REPORTS"
  local src; src=$(cd "$(dirname "$DEMO")" && pwd)/$(basename "$DEMO")
  cat >"$CD_ENV/demo-cdb.json" <<EOF
[{"directory": "$(dirname "$src")", "file": "$src",
  "arguments": ["clang", "-c", "$src", "-o", "/dev/null"]}]
EOF
  # Crosscheck fails the run unless Clang really has Z3 linked.
  "$(cc_bin)" analyze "$CD_ENV/demo-cdb.json" -o "$REPORTS" \
    --analyzers clangsa --enable core.NullDereference \
    --z3-refutation on \
    --analyzer-config clangsa:emit-constraint-snapshots=true
  # parse exits 2 when it finds defects, which is the expected outcome here.
  rc=0
  "$(cc_bin)" parse "$REPORTS" >"$CD_ENV/logs/parse.txt" 2>&1 || rc=$?
  [ "$rc" -le 2 ] || die "CodeChecker parse failed ($rc), see $CD_ENV/logs/parse.txt"
  grep -E '^\[|Found' "$CD_ENV/logs/parse.txt"
  grep -q 'core.NullDereference' "$CD_ENV/logs/parse.txt" || die "no NullDereference report"
}

cmd_server() {
  activate
  mkdir -p "$WORKSPACE"
  if curl -fs "$URL/../version" >/dev/null 2>&1 || lsof -ti tcp:"$PORT" >/dev/null 2>&1; then
    echo "server already listening on $PORT"; return
  fi
  nohup "$(cc_bin)" server -w "$WORKSPACE" --host localhost --port "$PORT" \
    >"$CD_ENV/logs/server.log" 2>&1 &
  echo $! >"$CD_ENV/server.pid"
  for _ in $(seq 60); do
    lsof -ti tcp:"$PORT" >/dev/null 2>&1 && { echo "server up: $URL"; return; }
    sleep 1
  done
  tail -20 "$CD_ENV/logs/server.log" >&2; die "server did not start"
}

# Waits for the server's graceful shutdown (several seconds: it stops every API
# and task worker in turn), so that `server` right after does not find the old
# one still listening. The pid is the CodeChecker wrapper, which forwards the
# signal and exits once the server has.
cmd_stop() {
  [ -f "$CD_ENV/server.pid" ] || { echo "no server.pid, nothing to stop"; return 0; }
  local pid; pid=$(cat "$CD_ENV/server.pid")
  if kill "$pid" 2>/dev/null; then
    for _ in $(seq 60); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.5
    done
    ! kill -0 "$pid" 2>/dev/null \
      || die "server $pid still shutting down after 30 s, see $CD_ENV/logs/server.log"
  fi
  rm -f "$CD_ENV/server.pid"
  ! lsof -ti tcp:"$PORT" -sTCP:LISTEN >/dev/null 2>&1 \
    || die "port $PORT is still taken by another process"
  echo "server stopped"
}

cmd_store() {
  activate
  [ -d "$REPORTS" ] || die "no reports, run: dev-loop.sh analyze"
  "$(cc_bin)" store "$REPORTS" -n "$RUN_NAME" --url "$URL"
  "$(cc_bin)" cmd results "$RUN_NAME" --url "$URL" -o plaintext
  echo "open: $URL/#run=$RUN_NAME"
}

cmd_status() {
  echo "clang:   $([ -x "$BUILD/bin/clang" ] && "$BUILD/bin/clang" --version | head -1 || echo missing)"
  echo "venv:    $([ -d "$VENV" ] && echo ok || echo missing)"
  echo "thrift:  $([ -d "$CC/codechecker_api/python" ] && echo ok || echo missing)"
  echo "web:     $([ -f "$CC/web/server/vue-cli/dist/index.html" ] && echo ok || echo missing)"
  echo "package: $([ -x "$(cc_bin)" ] && echo ok || echo missing)"
  echo "server:  $(lsof -ti tcp:"$PORT" >/dev/null 2>&1 && echo "up on $PORT" || echo down)"
}

# CodeChecker functional-test fixture: plists produced by the Colorful Day Clang
# from demo/two-path.c, one with Constraint Snapshots, one without, and one with
# snapshots but no SMT-LIB, as a Clang without Z3 writes them, and one with
# snapshots but no CFGs, as a Clang before the CFG side view wrote them, and
# one with CFGs but no exploded graph nodes, as the Clang of that view wrote
# them; one from
# demo/z3-refuted.c, whose Bug Path Z3 refutes; and one from
# demo/concrete-value.c, where a pointer holds a concrete address; and one
# from demo/opaque-call.c, where an opaque call replaces a global; and one
# from demo/several-contexts.c, one statement reached through two calls; and
# one from demo/call-result.c, whose symbol table has a call result and a
# value a checker made, and the same without the table, as a Clang before the
# table wrote it; and one from demo/replaced-field.c, a field of an object an
# opaque call replaced, and one from demo/widened-loop.c, values a widened loop
# replaced. Output
# goes into the CodeChecker test tree with the $FILE_PATH$ placeholder the
# functional tests expect, so re-running it is the only way to change them.
cmd_fixture() {
  use_clang
  local src=$CC/web/tests/projects/constraint_trace
  local variant dir flags
  for variant in with_snapshots no_snapshots; do
    dir=$src/$variant
    mkdir -p "$dir"
    cp "$DEMO" "$dir/two_path.c"
    flags=()
    [ "$variant" = with_snapshots ] \
      && flags=(-Xclang -analyzer-config -Xclang emit-constraint-snapshots=true)
    (cd "$dir" && clang --analyze --analyzer-output plist-multi-file \
      -Xclang -analyzer-checker=core "${flags[@]+"${flags[@]}"}" \
      -o two_path.plist "$dir/two_path.c")
    FIXTURE_DIR=$dir perl -pi -e 's/\Q$ENV{FIXTURE_DIR}\E/\$FILE_PATH\$/g' "$dir/two_path.plist"
    grep -q 'FILE_PATH' "$dir/two_path.plist" || die "placeholder missing in $dir"
    echo "fixture ok: $dir/two_path.plist"
  done
  # What a Clang without Z3 writes: the same trace minus its SMT-LIB.
  # Derived instead of built, so the fixture needs no second Clang build.
  grep -q '<key>smtlib</key><true/>' "$src/with_snapshots/two_path.plist" \
    || die "with_snapshots has no SMT-LIB; is $BUILD built with Z3?"
  dir=$src/no_smtlib
  mkdir -p "$dir"
  cp "$DEMO" "$dir/two_path.c"
  "$PYTHON" -I - "$CC/tools/report-converter" "$src/with_snapshots/two_path.plist" \
    "$dir/two_path.plist" <<'PY'
import plistlib, sys
sys.path.insert(0, sys.argv[1])
from codechecker_report_converter.report import constraint_trace
with open(sys.argv[2], 'rb') as f:
    plist = plistlib.load(f)
for diag in plist['diagnostics']:
    if 'constraint_trace' not in diag:
        continue
    trace = constraint_trace.ConstraintTrace(diag['constraint_trace'])
    nodes = []
    for index, node in enumerate(trace.nodes):
        snapshot = trace.snapshot(index)
        del snapshot['smt_declarations'], snapshot['smt_assertions']
        for variable in snapshot['variables']:
            variable.pop('smt', None)
            variable.pop('smt_signed', None)
        nodes.append({**{key: value for key, value in node.items()
                         if key not in constraint_trace.LISTS}, **snapshot})
    symbols = {dump: {key: value for key, value in symbol.items()
                      if key not in ('smt', 'smt_signed')}
               for dump, symbol in trace.symbols().items()}
    diag['constraint_trace'] = {
        **{key: value for key, value in trace.trace.items()
           if key not in ('smtlib', 'strings', 'exploded_nodes', 'symbols')},
        **constraint_trace.encode(nodes, trace.steps, symbols)}
with open(sys.argv[3], 'wb') as f:
    plistlib.dump(plist, f)
PY
  ! grep -qE '<key>smt|declare-fun|assert' "$dir/two_path.plist" || die "SMT-LIB left in $dir"
  echo "fixture ok: $dir/two_path.plist"

  # What a Clang from before trace format version 2 writes, and what reports
  # stored before it hold: every step with its whole snapshot, and the CFGs
  # as dicts in each trace rather than once per file.
  dir=$src/v1_trace
  mkdir -p "$dir"
  cp "$DEMO" "$dir/two_path.c"
  "$PYTHON" -I - "$CC/tools/report-converter" "$src/with_snapshots/two_path.plist" \
    "$dir/two_path.plist" <<'PY'
import plistlib, sys
sys.path.insert(0, sys.argv[1])
from codechecker_report_converter.report import constraint_trace
with open(sys.argv[2], 'rb') as f:
    plist = plistlib.load(f)
graphs = constraint_trace.read_graphs(
    plist.pop(constraint_trace.PLIST_GRAPHS, []))
for diag in plist['diagnostics']:
    if 'constraint_trace' not in diag:
        continue
    trace = constraint_trace.ConstraintTrace(
        constraint_trace.resolve_cfgs(diag['constraint_trace'], graphs))
    diag['constraint_trace'] = {
        'version': 1,
        'steps': [{**step, **trace.snapshot(step['exploded_node'])}
                  for step in trace.steps],
        'cfgs': trace.cfgs(),
        'exploded_nodes': [{key: value for key, value in node.items()
                            if key not in constraint_trace.LISTS
                            and key != 'cfg_position'}
                           for node in trace.nodes],
        'stack_frames': trace.trace['stack_frames']}
with open(sys.argv[3], 'wb') as f:
    plistlib.dump(plist, f)
PY
  grep -q '<key>symbol_ranges</key>' "$dir/two_path.plist" || die "no v1 steps in $dir"
  echo "fixture ok: $dir/two_path.plist"

  # z3_refuted: a Bug Path the range-based solver accepts and Z3 refutes, for a
  # Baseline Verdict that is not Feasible. Analyzed without crosscheck, which
  # would drop the report.
  # concrete_value: a pointer holding the concrete address &x, then null.
  # opaque_call: a global checked non-null, replaced by an opaque call, then
  # assumed null, so it holds two symbols along the Bug Path.
  # several_contexts: one statement reached through two calls.
  # call_result: a call result made in a callee the path leaves out, and a
  # malloc that unix.Malloc models.
  # replaced_field: a field of an object an opaque call replaced.
  # widened_loop: locals a widened loop replaced, with widening turned on.
  local name checkers widen
  for name in z3_refuted concrete_value opaque_call several_contexts \
      call_result replaced_field widened_loop; do
    dir=$src/$name
    mkdir -p "$dir"
    cp "$LLVM/.scratch/colorful-day/demo/${name//_/-}.c" "$dir/$name.c"
    checkers=core
    [ "$name" = call_result ] && checkers=core,unix.Malloc
    widen=()
    [ "$name" = widened_loop ] \
      && widen=(-Xclang -analyzer-config -Xclang widen-loops=true)
    (cd "$dir" && clang --analyze --analyzer-output plist-multi-file \
      -Xclang -analyzer-checker=$checkers \
      -Xclang -analyzer-config -Xclang emit-constraint-snapshots=true \
      "${widen[@]+"${widen[@]}"}" -o "$name.plist" "$dir/$name.c")
    FIXTURE_DIR=$dir perl -pi -e 's/\Q$ENV{FIXTURE_DIR}\E/\$FILE_PATH\$/g' "$dir/$name.plist"
    grep -q 'FILE_PATH' "$dir/$name.plist" || die "placeholder missing in $dir"
    echo "fixture ok: $dir/$name.plist"
  done

  # What a Clang from before the symbol table writes: the same trace minus
  # the table. The strings only it named stay, which readers do not mind.
  dir=$src/no_symbols
  mkdir -p "$dir"
  cp "$src/call_result/call_result.c" "$dir/call_result.c"
  "$PYTHON" -I - "$src/call_result/call_result.plist" "$dir/call_result.plist" <<'PY'
import plistlib, sys
with open(sys.argv[1], 'rb') as f:
    plist = plistlib.load(f)
for diag in plist['diagnostics']:
    del diag['constraint_trace']['symbols']
with open(sys.argv[2], 'wb') as f:
    plistlib.dump(plist, f)
PY
  ! grep -q '<key>symbols</key>' "$dir/call_result.plist" || die "table left in $dir"
  echo "fixture ok: $dir/call_result.plist"
}

# Clang lit tests of this feature, plus any extra lit paths passed as arguments.
cmd_lit() {
  use_clang
  build_lit_tools >/dev/null
  "$BUILD/bin/llvm-lit" -sv \
    "$LLVM/clang/test/Analysis/diagnostics/constraint-snapshots.c" \
    "$LLVM/clang/test/Analysis/diagnostics/constraint-snapshots-control.c" \
    "$LLVM/clang/test/Analysis/diagnostics/constraint-snapshots-smtlib.c" \
    "$LLVM/clang/test/Analysis/diagnostics/constraint-snapshots-no-z3.c" \
    "$LLVM/clang/test/Analysis/diagnostics/constraint-snapshots-cfg.c" \
    "$LLVM/clang/test/Analysis/diagnostics/constraint-snapshots-egraph.c" \
    "$LLVM/clang/test/Analysis/diagnostics/constraint-snapshots-delta.c" \
    "$LLVM/clang/test/Analysis/diagnostics/constraint-snapshots-symbols.c" \
    "$LLVM/clang/test/Analysis/analyzer-config.c" "$@"
}

# A global test server outlives a run that was killed or run straight through
# pytest. The Makefile then deletes its workspace (and the serverport file that
# names it) at the next run, so nothing can stop it any more and the new run
# starts on top of the orphan. Stop it while the serverport file is still there.
stop_stale_test_servers() {
  local root dir port
  root=$CC/build/workspace
  for dir in "$root"/global_simple_server "$root"/global_auth_server; do
    [ -f "$dir/serverport" ] || continue
    port=$(cat "$dir/serverport")
    echo "stopping stale test server on $port"
    HOME=$dir "$(cc_bin)" server --workspace "$dir" --port "$port" --stop \
      || echo "dev-loop: stale server on $port was not running" >&2
  done
}

# CodeChecker functional tests of this feature. Needs `package` and `env`.
cmd_functest() {
  activate; use_clang; use_test_tools
  stop_stale_test_servers
  # Through the Makefile target: it clears the test workspace and shuts down
  # the global test server, which otherwise goes stale between runs.
  make -C "$CC" test_web_feature TEST=tests/functional/constraint_trace \
    EXTRA_PYTEST_ARGS="$*"
}

# The store and report_viewer_api functional suites, which exercise the report
# storage path ticket 02 touched. Run in $CC_REPO; see `baseline`.
cmd_webtests() {
  activate; use_clang; use_test_tools
  local t rc=0
  for t in store report_viewer_api; do
    make -C "$CC" test_web_feature TEST=tests/functional/$t \
      >"$CD_ENV/logs/webtests-$t.log" 2>&1 || rc=1
    echo "$t: $(grep -E ' (passed|failed)' "$CD_ENV/logs/webtests-$t.log" | tail -1)"
  done
  return $rc
}

# Run webtests at another CodeChecker revision (default: the commit before the
# Colorful Day UI work) in a throwaway worktree under $CD_ENV, for comparing
# failures against a baseline. Needs docker (thrift stubs) and a built dist.
cmd_baseline() {
  local rev=${1:-a343881a2} wt=$CD_ENV/baseline-cc
  git -C "$CC" worktree add --detach "$wt" "$rev"
  mkdir -p "$wt/web/server/vue-cli"
  cp -R "$CC/web/server/vue-cli/dist" "$wt/web/server/vue-cli/dist"
  local rc=0
  (CC_REPO=$wt "$0" thrift && CC_REPO=$wt "$0" package && CC_REPO=$wt "$0" webtests) || rc=$?
  git -C "$CC" worktree remove --force "$wt"
  git -C "$CC" worktree prune
  return $rc
}

cmd_all() { cmd_env; cmd_thrift; cmd_web; cmd_package; cmd_analyze; cmd_server; cmd_store; }

TMUX_SRC=$CD_ENV/projects/tmux
TMUX_TAG=3.5a

# tmux with a compile database from bear. Configure needs Homebrew's libevent
# and ncurses through pkg-config, and an explicit utf8proc choice on macOS.
tmux_cdb() {
  [ -d "$TMUX_SRC/.git" ] || git clone -q --depth 1 --branch "$TMUX_TAG" \
    https://github.com/tmux/tmux.git "$TMUX_SRC"
  [ -f "$TMUX_SRC/compile_commands.json" ] && return 0
  command -v bear >/dev/null || die "bear missing: brew install bear"
  (cd "$TMUX_SRC" \
    && sh autogen.sh \
    && PKG_CONFIG_PATH=/opt/homebrew/opt/libevent/lib/pkgconfig:/opt/homebrew/opt/ncurses/lib/pkgconfig \
       ./configure --disable-utf8proc \
    && bear --output compile_commands.json -- make -j"$(sysctl -n hw.ncpu)") \
    >"$CD_ENV/logs/tmux-build.log" 2>&1 \
    || { tail -20 "$CD_ENV/logs/tmux-build.log" >&2; die "tmux build failed"; }
}

# reportId of the one report of a run at file:line, from `cmd results`.
report_id() {
  "$(cc_bin)" cmd results "$1" --url "$URL" -o json 2>/dev/null \
    | "$PYTHON" -I -c '
import json, os, sys
hits = [r["reportId"] for r in json.load(sys.stdin)
        if os.path.basename(r["checkedFile"]) == sys.argv[1]
        and r["line"] == int(sys.argv[2])]
if len(hits) != 1:
    sys.exit(f"expected one report at {sys.argv[1]}:{sys.argv[2]}, got {hits}")
print(hits[0])' "$2" "$3"
}

# The demo data from a clean server: its own workspace, wiped every time, so
# the dev workspace of earlier tickets is left alone. Stores the short
# two-path example, all of tmux and the several-contexts example, and prints
# the three report URLs the script in demo/README.md opens.
cmd_demo() {
  activate; use_clang
  cmd_stop
  rm -rf "$DEMO_WORKSPACE"
  WORKSPACE=$DEMO_WORKSPACE cmd_server

  DEMO=$LLVM/.scratch/colorful-day/demo/two-path-short.c cmd_analyze
  RUN_NAME=colorful-day-two-path cmd_store >/dev/null

  tmux_cdb
  # cmd_store re-sources the venv, whose activate restores the PATH saved at
  # the first activation, so the Colorful Day Clang is gone again.
  use_clang
  local out=$CD_ENV/reports-tmux
  rm -rf "$out"
  "$(cc_bin)" analyze "$TMUX_SRC/compile_commands.json" -o "$out" \
    --analyzers clangsa -j"$(sysctl -n hw.ncpu)" --z3-refutation on \
    --analyzer-config clangsa:emit-constraint-snapshots=true \
    >"$CD_ENV/logs/tmux-analyze.log" 2>&1 \
    || { tail -20 "$CD_ENV/logs/tmux-analyze.log" >&2; die "tmux analysis failed"; }
  "$(cc_bin)" store "$out" -n colorful-day-tmux --url "$URL" >/dev/null

  DEMO=$LLVM/.scratch/colorful-day/demo/several-contexts.c cmd_analyze
  RUN_NAME=colorful-day-contexts cmd_store >/dev/null

  echo "two-path: $URL/report-detail?report-id=$(report_id colorful-day-two-path two-path-short.c 10)"
  echo "tmux:     $URL/report-detail?report-id=$(report_id colorful-day-tmux grid.c 1073)"
  echo "contexts: $URL/report-detail?report-id=$(report_id colorful-day-contexts several-contexts.c 9)"
}

sub=${1:-}; shift || true
case "$sub" in
  env|clang|thrift|web|package|analyze|server|stop|store|status|all|fixture|lit|functest|webtests|baseline|demo) "cmd_$sub" "$@" ;;
  *) die "usage: $0 <env|clang|thrift|web|package|analyze|server|stop|store|status|all|fixture|lit|functest|webtests|baseline|demo>" ;;
esac
