// Test that --ast-diff produces output and correctly filters trivial changes.
// A single function gaining noexcept with no downstream effects should
// produce "No meaningful AST differences" after filtering.
//
// RUN: %gen_compdb %s > %t.json
// RUN: rm -rf %t.output
// RUN: mkdir -p %t.output
// RUN: %clang_exception_scan --ast-diff %t.json %t.output
//
// With filtering on (default), this trivial case has no meaningful diff.
// RUN: cat %t.output/ast_diff.txt | FileCheck %s --check-prefix=CHECK-FILTERED
// CHECK-FILTERED: No meaningful AST differences found.
//
// With trivial-noexcept filtering off, the FunctionDecl change should appear.
// RUN: rm -rf %t.output2
// RUN: mkdir -p %t.output2
// RUN: %clang_exception_scan --ast-diff --diff-filter-trivial-noexcept=false %t.json %t.output2
// RUN: cat %t.output2/ast_diff.txt | FileCheck %s --check-prefix=CHECK-UNFILTERED
// CHECK-UNFILTERED: === {{.*}}ast_diff_manifest.cpp ===
// CHECK-UNFILTERED: FunctionDecl {{.*}} noexcept

void safe() {}
