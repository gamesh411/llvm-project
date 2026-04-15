#!/bin/bash
# Test: verify that implicit template instantiation USRs are registered
# in USRToFunctionMap (no "USR not found" errors).
#
# This test catches a regression where shouldVisitTemplateInstantiations()
# was not overridden in the USR mapping visitor, causing instantiated
# methods like vector<int>::push_back(int&&) to be missing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INPUT="$SCRIPT_DIR/Inputs/usr-mapping-template-instantiation.cpp"

# Find the built binary relative to the build dir
SCAN_BIN="${CLANG_EXCEPTION_SCAN:-$(dirname "$0")/../../../../llvm/out/build/relwithdebug/bin/clang-exception-scan}"
CLANGXX="${CLANGXX:-$(dirname "$SCAN_BIN")/clang++}"

if [ ! -x "$SCAN_BIN" ]; then
    echo "SKIP: clang-exception-scan not found at $SCAN_BIN"
    exit 0
fi

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Find system C++ headers
SYSROOT=$(xcrun --show-sdk-path 2>/dev/null || echo "")
EXTRA_FLAGS=""
if [ -n "$SYSROOT" ]; then
    EXTRA_FLAGS="-isystem $SYSROOT/usr/include/c++/v1 -isystem $SYSROOT/usr/include"
fi

# Create compilation database
cat > "$TMPDIR/compile_commands.json" <<EOF
[{
  "directory": "$TMPDIR",
  "command": "$CLANGXX -std=c++17 $EXTRA_FLAGS -c $INPUT",
  "file": "$INPUT"
}]
EOF

OUTPUT="$TMPDIR/output"
mkdir -p "$OUTPUT"

# Run analysis, capture stderr for "USR not found" messages
STDERR_FILE="$TMPDIR/stderr.txt"
"$SCAN_BIN" "$TMPDIR/compile_commands.json" "$OUTPUT" 2>"$STDERR_FILE" || true

# Check: no "USR not found" for push_back
if grep -q "USR not found.*push_back" "$STDERR_FILE"; then
    echo "FAIL: push_back USR not found in USRToFunctionMap"
    grep "USR not found.*push_back" "$STDERR_FILE"
    exit 1
fi

echo "PASS: all template instantiation USRs registered"
