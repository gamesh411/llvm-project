// REQUIRES: z3
// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/out.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-delta.py %t/out.plist \
// RUN:   | FileCheck %s --implicit-check-not=BAD
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/out.plist path_condition \
// RUN:   | FileCheck %s --check-prefix=PC

// Each check narrows one more parameter, which is dead after its check. So
// each node after the first swaps one known range for the next and adds one
// path condition entry with its assertion, while the variables and their
// declarations are listed once, until `p = 0` changes one of them.
int chain(int *p, int a0, int a1, int a2, int a3) {
  if (a0 != 1)
    return 0;
  if (a1 != 2)
    return 0;
  if (a2 != 3)
    return 0;
  if (a3 != 4)
    return 0;
  p = 0;
  return *p; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// CHECK: STRINGS
// CHECK-NEXT: N0 ranges +1 ~0 -0 vars +5 ~0 -0 pc +1 ~0 -0 decls +5 ~0 -0{{$}}
// CHECK-NEXT: N1 ranges +1 ~0 -1 pc +1 ~0 -0{{$}}
// CHECK-NEXT: N2 ranges +1 ~0 -1 pc +1 ~0 -0{{$}}
// CHECK-NEXT: N3 ranges +1 ~0 -1 pc +1 ~0 -0{{$}}
// CHECK-NEXT: N4 ranges +0 ~0 -1 vars +0 ~1 -0 decls +0 ~0 -1{{$}}
// CHECK-NEXT: N5{{$}}
// CHECK-NEXT: N6{{$}}

// The full path condition is still there at every step.
// PC: EVENT "Assuming 'a3' is equal to 4": reg_$[[#]]<int a0> = { [1, 1] }; reg_$[[#]]<int a1> = { [2, 2] }; reg_$[[#]]<int a2> = { [3, 3] }; reg_$[[#]]<int a3> = { [4, 4] }{{$}}
