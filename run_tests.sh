#!/bin/bash

# Test script for StoreToImmutableChecker with system macro examples
# This script helps verify that the SM.isInSystemMacro check works correctly

echo "=== Testing StoreToImmutableChecker with System Macros ==="
echo

# Function to run static analyzer on a file
run_analyzer() {
    local file=$1
    local lang=$2
    echo "Testing $file..."
    
    if [ "$lang" = "cpp" ]; then
        clang++ --analyze -Xanalyzer -analyzer-checker=alpha.cplusplus.StoreToImmutable \
                -Xanalyzer -analyzer-output=text "$file" 2>&1 | grep -E "(warning|error|StoreToImmutable)" || echo "No issues found (expected for system macros)"
    else
        clang --analyze -Xanalyzer -analyzer-checker=alpha.cplusplus.StoreToImmutable \
              -Xanalyzer -analyzer-output=text "$file" 2>&1 | grep -E "(warning|error|StoreToImmutable)" || echo "No issues found (expected for system macros)"
    fi
    echo
}

# Test C files
echo "--- C Tests (Read-only operations) ---"
run_analyzer "test_system_macro.c" "c"
run_analyzer "test_system_macro_targeted.c" "c"

# Test C++ files
echo "--- C++ Tests (Read-only operations) ---"
run_analyzer "test_system_macro.cpp" "cpp"

# Test binding-focused files (actual writes to const memory)
echo "--- C Tests (Binding operations - actual writes to const memory) ---"
run_analyzer "test_system_macro_binding.c" "c"
run_analyzer "test_system_header_simulation.c" "c"

echo "--- C++ Tests (Binding operations - actual writes to const memory) ---"
run_analyzer "test_system_macro_binding.cpp" "cpp"

echo "=== Test Summary ==="
echo "These tests demonstrate scenarios where the StoreToImmutableChecker"
echo "should NOT report warnings because the operations occur within system macros."
echo
echo "Key points:"
echo "1. The checker should skip reporting when SM.isInSystemMacro() returns true"
echo "2. System macros like assert, offsetof, va_start, va_end, setjmp, longjmp"
echo "   should not trigger warnings even when they involve const memory"
echo "3. This prevents false positives from system library code"
echo "4. The binding-focused tests demonstrate actual writes to const memory"
echo "   that should be skipped when they occur in system macros"
echo
echo "To see the actual behavior, run:"
echo "  clang --analyze -Xanalyzer -analyzer-checker=alpha.cplusplus.StoreToImmutable test_system_header_simulation.c"
echo
echo "The most interesting tests are:"
echo "- test_system_macro_binding.c: Direct writes to const memory in macros"
echo "- test_system_header_simulation.c: Realistic system header scenarios"
echo "- test_system_macro_binding.cpp: C++ version with const object writes" 