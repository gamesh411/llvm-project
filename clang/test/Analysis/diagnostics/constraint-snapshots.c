// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/on.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/on.plist | FileCheck %s --implicit-check-not=MISSING
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/on.plist path_condition | FileCheck %s --check-prefix=PC
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/on.plist variables | FileCheck %s --check-prefix=VARS

// With the option off, plist output carries no trace and matches the default.
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -o %t/default.plist -verify %s
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=false -o %t/off.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/off.plist | FileCheck %s --check-prefix=OFF
// RUN: diff %t/default.plist %t/off.plist

// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/raw.plist -verify %s
// RUN: FileCheck %s --check-prefix=RAW --input-file %t/raw.plist

// OFF-NOT: TRACE
// OFF: NO-TRACE
// OFF-NEXT: NO-TRACE

// Every event carries a snapshot; a missing one would print MISSING.

int two_step(int *p, int a) {
  if (a == 0)
    p = 0;
  return *p + a; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// `a` is read after the dereference, so its range stays live on every step.
// CHECK: TRACE version 2
// CHECK-NEXT: EVENT "Assuming 'a' is equal to 0": reg_$[[A:[0-9]+]]<int a> = { [0, 0] }
// CHECK-NEXT: EVENT "Null pointer value stored to 'p'": reg_$[[A]]<int a> = { [0, 0] }
// CHECK-NEXT: EVENT "Dereference of null pointer (loaded from variable 'p')": reg_$[[A]]<int a> = { [0, 0] }

static void set_null_if_flagged(int **pp, int flag) {
  if (flag)
    *pp = 0;
}

int through_call(int *p, int flag) {
  set_null_if_flagged(&p, flag);
  return *p + flag; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// Inlined calls add their own events: the snapshot taken at the call is empty,
// the one at the return holds what the callee assumed.
// CHECK: TRACE version 2
// CHECK-NEXT: EVENT "Calling 'set_null_if_flagged'": {{$}}
// CHECK-NEXT: EVENT "Entered call from 'through_call'": {{$}}
// CHECK-NEXT: EVENT "Assuming 'flag' is not equal to 0": reg_$[[F:[0-9]+]]<int flag> = { [-2147483648, -1], [1, 2147483647] }
// CHECK-NEXT: EVENT "Null pointer value stored to 'p'": reg_$[[F]]<int flag> = { [-2147483648, -1], [1, 2147483647] }
// CHECK-NEXT: EVENT "Returning from 'set_null_if_flagged'": reg_$[[F]]<int flag> = { [-2147483648, -1], [1, 2147483647] }
// CHECK-NEXT: EVENT "Dereference of null pointer (loaded from variable 'p')": reg_$[[F]]<int flag> = { [-2147483648, -1], [1, 2147483647] }

// `dying` is never read after the branch: the analyzer drops it, so the last
// step knows nothing about it, while the path condition still holds it.
int dead_symbol(int *q, int dying) {
  if (dying == 0)
    q = 0;
  return *q; // expected-warning{{Dereference of null pointer (loaded from variable 'q')}}
}

// CHECK: EVENT "Assuming 'dying' is equal to 0": reg_$[[D:[0-9]+]]<int dying> = { [0, 0] }
// CHECK: EVENT "Dereference of null pointer (loaded from variable 'q')": {{$}}
// PC: EVENT "Assuming 'dying' is equal to 0": reg_$[[PD:[0-9]+]]<int dying> = { [0, 0] }
// PC: EVENT "Null pointer value stored to 'q'": reg_$[[PD]]<int dying> = { [0, 0] }
// PC: EVENT "Dereference of null pointer (loaded from variable 'q')": reg_$[[PD]]<int dying> = { [0, 0] }

// Variables resolve to their symbol or concrete value at each step; `dying` is
// a parameter, so it still has its value after the analyzer dropped it.
// VARS: EVENT "Assuming 'dying' is equal to 0": dying = reg_$[[VD:[0-9]+]]<int dying> [symbol]; q = reg_$[[VQ:[0-9]+]]<int * q> [symbol]{{$}}
// VARS: EVENT "Null pointer value stored to 'q'": dying = reg_$[[VD]]<int dying> [symbol]; q = 0 [integer]{{$}}
// VARS: EVENT "Dereference of null pointer (loaded from variable 'q')": dying = reg_$[[VD]]<int dying> [symbol]; q = 0 [integer]{{$}}

// Only direct bindings exist for locals and inlined parameters, and a parameter
// written and then dropped has lost its value rather than kept the initial one.
int reassigned_parameter(int *r, int written) {
  written = 5;
  r = 0;
  return *r; // expected-warning{{Dereference of null pointer (loaded from variable 'r')}}
}

// VARS: EVENT "Null pointer value stored to 'r'": r = 0 [integer]{{$}}
// VARS: EVENT "Dereference of null pointer (loaded from variable 'r')": r = 0 [integer]{{$}}

int *global_pointer;

int reads_a_global(void) {
  if (global_pointer != 0)
    return 0;
  return *global_pointer; // expected-warning{{Dereference of null pointer (loaded from variable 'global_pointer')}}
}

// A global has no binding until it is written, but the function can name it.
// VARS: EVENT "Assuming 'global_pointer' is equal to null": global_pointer = reg_$[[G:[0-9]+]]<int * global_pointer> [symbol]{{$}}
// VARS: EVENT "Dereference of null pointer (loaded from variable 'global_pointer')": global_pointer = reg_$[[G]]<int * global_pointer> [symbol]{{$}}

int shadowed_variable(int *s) {
  int shadow = 1;
  {
    int shadow = 2;
    s = 0;
    (void)shadow;
  }
  return *s + shadow; // expected-warning{{Dereference of null pointer (loaded from variable 's')}}
}

// While both are bound, the name means the inner declaration.
// VARS: EVENT "Null pointer value stored to 's'": s = 0 [integer]; shadow = 2 [integer]{{$}}

// The raw plist nests the trace under the diagnostic after the path. A step
// names the node whose snapshot it shows, a node lists what changed since the
// node before it, and the entries are indices into the trace's strings.
// RAW: <key>path</key>
// RAW: <key>constraint_trace</key>
// RAW-NEXT: <dict>
// RAW-NEXT: <key>version</key><integer>2</integer>
// RAW: <key>steps</key>
// RAW-NEXT: <array>
// RAW-NEXT: <dict>
// RAW-NEXT: <key>path_index</key><integer>[[#]]</integer>
// RAW-NEXT: <key>exploded_node</key><integer>0</integer>
// RAW-NEXT: </dict>
// RAW: <key>exploded_nodes</key>
// RAW: <key>symbol_ranges</key>
// RAW-NEXT: <dict>
// RAW-NEXT: <key>insert</key>
// RAW-NEXT: <array>
// RAW-NEXT: <array><integer>0</integer><integer>0</integer><integer>1</integer></array>
// RAW-NEXT: </array>
// RAW-NEXT: </dict>
// RAW: <key>strings</key>
// RAW-NEXT: <array>
// RAW-NEXT: <string>reg_$[[#]]&lt;int a&gt;</string>
// RAW-NEXT: <string>{ [0, 0] }</string>
