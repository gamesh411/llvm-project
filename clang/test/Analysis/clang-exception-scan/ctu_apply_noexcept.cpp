// Test that --apply-noexcept works correctly with cross-TU analysis.
// A function calling a safe function defined in another TU should get noexcept.
//
// RUN: %gen_compdb %s %S/Inputs/ctu_apply_impl.cpp > %t.json
// RUN: rm -rf %t.output
// RUN: mkdir -p %t.output
// RUN: %clang_exception_scan --apply-noexcept %t.json %t.output
//
// The cross-TU callee is safe, so the caller should be marked noexcept.
// RUN: cat %t.output/definite_results.txt | FileCheck %s --check-prefix=CHECK-DEFINITE
// RUN: cat %t.output/applied/ctu_apply_noexcept.cpp | FileCheck %s --check-prefix=CHECK-APPLIED

// CHECK-DEFINITE: c:@F@calls_cross_tu_safe# defined in
// CHECK-APPLIED: void calls_cross_tu_safe() noexcept {

void cross_tu_safe();

void calls_cross_tu_safe() {
  cross_tu_safe();
}

// The throwing callee should prevent noexcept — not a definite match.
// CHECK-DEFINITE-NOT: c:@F@calls_cross_tu_throwing#

void cross_tu_throwing();

// Verify the throwing caller was NOT given noexcept in the applied output.
// CHECK-APPLIED: void calls_cross_tu_throwing() {
void calls_cross_tu_throwing() {
  cross_tu_throwing();
}
