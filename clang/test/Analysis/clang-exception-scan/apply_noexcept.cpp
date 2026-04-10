// Test that --apply-noexcept inserts noexcept on definite-match functions
// and writes the modified files to output-dir/applied/.
//
// RUN: %gen_compdb %s > %t.json
// RUN: rm -rf %t.output
// RUN: mkdir -p %t.output
// RUN: %clang_exception_scan --apply-noexcept %t.json %t.output
//
// Check that the applied directory was created with a rewritten file.
// RUN: ls %t.output/applied/ | FileCheck %s --check-prefix=CHECK-FILES
// CHECK-FILES: apply_noexcept.cpp
//
// Check that noexcept was inserted on the right functions.
// RUN: cat %t.output/applied/apply_noexcept.cpp | FileCheck %s --check-prefix=CHECK-APPLIED
//
// Also verify the definite_results.txt to confirm which functions were detected.
// RUN: cat %t.output/definite_results.txt | FileCheck %s --check-prefix=CHECK-DEFINITE

#include "Inputs/stdexcept.h"

// CHECK-DEFINITE: c:@F@safe_empty# defined in
// CHECK-APPLIED: void safe_empty() noexcept {}
void safe_empty() {}

// CHECK-DEFINITE: c:@F@safe_returns_int# defined in
// CHECK-APPLIED: int safe_returns_int() noexcept { return 42; }
int safe_returns_int() { return 42; }

// Already noexcept — should NOT be in definite results, should be unchanged.
// CHECK-DEFINITE-NOT: c:@F@already_noexcept#
// CHECK-APPLIED: void already_noexcept() noexcept {}
void already_noexcept() noexcept {}

// Throws — should NOT be in definite results, should be unchanged.
// CHECK-DEFINITE-NOT: c:@F@throws#
// CHECK-APPLIED: void throws() { throw std::runtime_error("boom"); }
void throws() { throw std::runtime_error("boom"); }

// Catches everything — should be a definite match.
// CHECK-DEFINITE: c:@F@catches_all# defined in
// CHECK-APPLIED: void catches_all() noexcept {
void catches_all() {
  try {
    throws();
  } catch (...) {
  }
}

// Calls unknown — should NOT be a definite match, should be unchanged.
int unknown_func();
// CHECK-DEFINITE-NOT: c:@F@calls_unknown#
// CHECK-APPLIED: void calls_unknown() { unknown_func(); }
void calls_unknown() { unknown_func(); }
