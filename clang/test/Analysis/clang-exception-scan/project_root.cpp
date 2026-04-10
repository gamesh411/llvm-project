// Test that --project-root restricts which files get modified.
// We use a two-TU setup where the external file is in Inputs/.
// With --project-root pointing only at Inputs/, only the external file
// should be modified (not the main test file).
//
// RUN: %gen_compdb %s %S/Inputs/project_root_external.cpp > %t.json
// RUN: rm -rf %t.output
// RUN: mkdir -p %t.output
//
// Run with project-root = Inputs dir only. The main file is outside that prefix.
// RUN: %clang_exception_scan --apply-noexcept --project-root=%S/Inputs %t.json %t.output
//
// Only the external file should appear in applied/ — the main file is outside project-root.
// RUN: ls %t.output/applied/ | FileCheck %s --check-prefix=CHECK-RESTRICTED
// CHECK-RESTRICTED: project_root_external.cpp
// CHECK-RESTRICTED-NOT: project_root.cpp
//
// Now run with project-root covering both files.
// RUN: rm -rf %t.output2
// RUN: mkdir -p %t.output2
// RUN: %clang_exception_scan --apply-noexcept --project-root=%S %t.json %t.output2
//
// Both files should appear.
// RUN: ls %t.output2/applied/ | FileCheck %s --check-prefix=CHECK-BOTH
// CHECK-BOTH-DAG: project_root.cpp
// CHECK-BOTH-DAG: project_root_external.cpp

#include "Inputs/stdexcept.h"

void safe_in_main() {}
