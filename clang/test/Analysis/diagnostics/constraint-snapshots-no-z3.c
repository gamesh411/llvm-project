// UNSUPPORTED: z3
// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/on.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/on.plist | FileCheck %s
// RUN: FileCheck %s --check-prefix=RAW --input-file %t/on.plist

// Without Z3 there is no SMT-LIB, but the readable ranges are still there.
// RAW-NOT: <key>smt

int two_step(int *p, int a) {
  if (a == 0)
    p = 0;
  return *p + a; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// CHECK: TRACE version 2
// CHECK-NEXT: EVENT "Assuming 'a' is equal to 0": reg_$[[A:[0-9]+]]<int a> = { [0, 0] }
