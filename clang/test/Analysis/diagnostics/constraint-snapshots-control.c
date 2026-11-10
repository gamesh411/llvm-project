// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/out.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/out.plist symbol_ranges control | FileCheck %s --check-prefix=RANGES
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/out.plist variables control | FileCheck %s --check-prefix=VARS

// Every control-flow piece carries a snapshot too; a missing one prints MISSING.
// RANGES-NOT: MISSING
// VARS-NOT: MISSING

int branch_step(int *p, int a) {
  if (a == 0)
    p = 0;
  return *p + a; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// The edge into the branch target shows the assumption the branch made.
// RANGES: CONTROL ending at [[@LINE-5]]:5: reg_$[[A:[0-9]+]]<int a> = { [0, 0] }{{$}}
// VARS: CONTROL ending at [[@LINE-6]]:5: a = reg_$[[VA:[0-9]+]]<int a> [symbol]; p = 0 [integer]{{$}}

int loop_step(int *p) {
  int total = 0;
  for (int i = 0; i < 3; ++i) {
    if (i == 2)
      p = 0;
    total = total + i;
  }
  return *p + total; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// A location visited several times keeps one step per visit, each with the
// values of its own iteration.
// VARS: CONTROL ending at [[@LINE-9]]:5: i = 0 [integer]; p = reg_$[[P:[0-9]+]]<int * p> [symbol]; total = 0 [integer]{{$}}
// VARS: CONTROL ending at [[@LINE-10]]:5: i = 1 [integer]; p = reg_$[[P]]<int * p> [symbol]; total = 0 [integer]{{$}}
// VARS: CONTROL ending at [[@LINE-11]]:5: i = 2 [integer]; p = reg_$[[P]]<int * p> [symbol]; total = 1 [integer]{{$}}

int merged_step(int *p) {
  int x = 1;
  x = 2;
  x = 3;
  x = 4;
  p = 0;
  return *p + x; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// The edge from the first statement to `p = 0` is merged out of per-statement
// edges. It must show the later node's values, x = 4; keeping the first
// piece's snapshot would show x = 1 at this step.
// VARS: CONTROL ending at [[@LINE-7]]:3: p = 0 [integer]; x = 4 [integer]{{$}}
