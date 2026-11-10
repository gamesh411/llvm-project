#!/usr/bin/env bash
# Colorful Day dev loop: Clang build -> CodeChecker analyze -> store -> server -> browser.
# Re-runnable; every step fails loudly. All generated state lives under $CD_ENV.
# Usage: dev-loop.sh <env|thrift|web|package|clang|analyze|store|server|stop|status|all|fixture|lit|functest|webtests|baseline> [args]
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
  python -c 'import lxml, sqlalchemy, thrift' && echo 'env ok'
}

cmd_clang() {
  [ -d "$BUILD" ] || die "configure $BUILD first (see ticket 01 comments)"
  # llvm-config is only needed by llvm-lit, see `lit`.
  (cd "$BUILD" && ninja clang FileCheck not count llvm-config)
  # Tools the rest of clang/test/Analysis needs: Scalable/ssaf-*, func-mapping.
  # A stale clang-extdef-mapping or clang fails func-mapping-test.cpp with
  # "unable to load precompiled file" (the AST embeds the build revision).
  (cd "$BUILD" && ninja clang-ssaf-analyzer clang-ssaf-format clang-ssaf-linker \
    clang-ssaf-src-edit-merge SSAFExamplePlugin SSAFTestTransformationPlugin \
    split-file clang-extdef-mapping yaml2obj)
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

cmd_stop() {
  [ -f "$CD_ENV/server.pid" ] && kill "$(cat "$CD_ENV/server.pid")" 2>/dev/null || true
  rm -f "$CD_ENV/server.pid"
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
# from demo/two-path.c, one with Constraint Snapshots and one without. Output
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
}

# Clang lit tests of this feature, plus any extra lit paths passed as arguments.
cmd_lit() {
  use_clang
  (cd "$BUILD" && ninja clang FileCheck not count llvm-config >/dev/null)
  "$BUILD/bin/llvm-lit" -sv \
    "$LLVM/clang/test/Analysis/diagnostics/constraint-snapshots.c" \
    "$LLVM/clang/test/Analysis/analyzer-config.c" "$@"
}

# CodeChecker functional tests of this feature. Needs `package` and `env`.
cmd_functest() {
  activate; use_clang; use_test_tools
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

sub=${1:-}; shift || true
case "$sub" in
  env|clang|thrift|web|package|analyze|server|stop|store|status|all|fixture|lit|functest|webtests|baseline) "cmd_$sub" "$@" ;;
  *) die "usage: $0 <env|clang|thrift|web|package|analyze|server|stop|store|status|all|fixture|lit|functest>" ;;
esac
