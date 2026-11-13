#!/usr/bin/env bash
# Colorful Day handoff: bring the `defects` run to another machine.
# Usage: handoff.sh <view|rerun>
#   view   store the example reports of this folder as run $RUN_NAME (`defects`)
#   rerun  analyze the same files with this machine's Clang, store as
#          $RUN_NAME-rerun
# Both need the CodeChecker dev package and a running server (dev-loop.sh).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
LLVM=${LLVM:-$(cd "$HERE/../../.." && pwd)}
CC=${CC_REPO:-$HOME/codechecker}
CD_ENV=${CD_ENV:-$HOME/colorful-day-env}
BUILD=${CLANG_BUILD:-$LLVM/build-colorful}
# The LLVM build without assertions whose compile commands and generated
# headers the analysis of the LLVM files uses.
NDEBUG_BUILD=${NDEBUG_BUILD:-$CD_ENV/llvm-scale/build}
TMUX_SRC=${TMUX_SRC:-$CD_ENV/projects/tmux}
PORT=${CD_PORT:-8002}
RUN_NAME=${RUN_NAME:-defects}
VENV=${VENV:-$CD_ENV/venv}
URL=http://localhost:$PORT/Default
OUT=$CD_ENV/handoff

die() { echo "handoff: $*" >&2; exit 1; }

setup() {
  [ -f "$VENV/bin/activate" ] || die "venv missing, run: dev-loop.sh env"
  # shellcheck disable=SC1091
  . "$VENV/bin/activate"
  CODECHECKER=$CC/build/CodeChecker/bin/CodeChecker
  [ -x "$CODECHECKER" ] || die "no $CODECHECKER, run: dev-loop.sh package"
  curl -fs "$URL/../version" >/dev/null 2>&1 \
    || die "no server on port $PORT, run: dev-loop.sh server"
  mkdir -p "$OUT"
}

# The reports and compile commands name the paths of the machine that made
# them. The longer prefixes come first, as they lie under the shorter ones.
relocate() {
  sed -i.orig \
    -e "s|/Users/efulop/llvm-project/build-colorful|$BUILD|g" \
    -e "s|/Users/efulop/colorful-day-env/llvm-scale/build|$NDEBUG_BUILD|g" \
    -e "s|/Users/efulop/colorful-day-env/projects/tmux|$TMUX_SRC|g" \
    -e "s|/Users/efulop/colorful-day-env|$CD_ENV|g" \
    -e "s|/Users/efulop/llvm-project|$LLVM|g" \
    -e "s|/Users/efulop/codechecker|$CC|g" \
    "$@"
  for file in "$@"; do rm -f "$file.orig"; done
}

# CodeChecker leaves out a report when a file it names is missing or newer
# than the report, without failing, so both are settled before storing.
check_sources() {
  python - "$@" <<'EOF'
import glob, os, plistlib, sys

missing = {}
for directory in sys.argv[1:]:
    for path in sorted(glob.glob(os.path.join(directory, "*.plist"))):
        with open(path, "rb") as plist:
            for name in plistlib.load(plist)["files"]:
                if not os.path.exists(name):
                    missing.setdefault(name, []).append(os.path.basename(path))
for name, reports in sorted(missing.items()):
    print(f"missing: {name}\n  named by: {', '.join(sorted(set(reports)))}")
sys.exit(1 if missing else 0)
EOF
}

cmd_view() {
  setup
  rm -rf "$OUT/defects" "$OUT/tmux-grid"
  tar -xzf "$HERE/example-reports.tar.gz" -C "$OUT"
  find "$OUT/defects" "$OUT/tmux-grid" -type f | while read -r file; do
    relocate "$file"
  done
  check_sources "$OUT/defects" "$OUT/tmux-grid" \
    || die "the files above are not on this machine, see README.md"
  find "$OUT/defects" "$OUT/tmux-grid" -name '*.plist' -exec touch {} +
  "$CODECHECKER" store "$OUT/defects" "$OUT/tmux-grid" -n "$RUN_NAME" --url "$URL"
  echo "open: $URL/reports?run=$RUN_NAME"
}

cmd_rerun() {
  setup
  [ -x "$BUILD/bin/clang" ] || die "no $BUILD/bin/clang, run: dev-loop.sh clang"
  [ -d "$NDEBUG_BUILD/include/llvm" ] \
    || die "no LLVM build at $NDEBUG_BUILD, see README.md"
  [ -f "$TMUX_SRC/grid.c" ] || die "no tmux at $TMUX_SRC, see README.md"
  export PATH=$BUILD/bin:$PATH
  cp "$HERE/cdb-llvm.json" "$HERE/cdb-tmux-grid.json" "$OUT/"
  relocate "$OUT/cdb-llvm.json" "$OUT/cdb-tmux-grid.json"
  local name
  for name in llvm tmux-grid; do
    rm -rf "$OUT/rerun-$name"
    "$CODECHECKER" analyze "$OUT/cdb-$name.json" -o "$OUT/rerun-$name" \
      --analyzers clangsa -j8 --z3-refutation on \
      --analyzer-config clangsa:emit-constraint-snapshots=true \
      >"$OUT/rerun-$name.log" 2>&1 \
      || { tail -20 "$OUT/rerun-$name.log" >&2; die "analysis of $name failed"; }
    grep -E 'Successfully analyzed|Failed to analyze' -A1 "$OUT/rerun-$name.log"
  done
  "$CODECHECKER" store "$OUT/rerun-llvm" "$OUT/rerun-tmux-grid" \
    -n "$RUN_NAME-rerun" --url "$URL"
  echo "open: $URL/reports?run=$RUN_NAME-rerun"
}

case "${1:-}" in
  view) cmd_view ;;
  rerun) cmd_rerun ;;
  *) die "usage: handoff.sh <view|rerun>" ;;
esac
