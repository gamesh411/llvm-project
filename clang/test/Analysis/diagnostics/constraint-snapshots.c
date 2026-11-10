// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/on.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/on.plist | FileCheck %s

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
// CHECK-NOT: MISSING

int two_step(int *p, int a) {
  if (a == 0)
    p = 0;
  return *p + a; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// `a` is read after the dereference, so its range stays live on every step.
// CHECK: TRACE version 1
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
// CHECK: TRACE version 1
// CHECK-NEXT: EVENT "Calling 'set_null_if_flagged'": {{$}}
// CHECK-NEXT: EVENT "Entered call from 'through_call'": {{$}}
// CHECK-NEXT: EVENT "Assuming 'flag' is not equal to 0": reg_$[[F:[0-9]+]]<int flag> = { [-2147483648, -1], [1, 2147483647] }
// CHECK-NEXT: EVENT "Null pointer value stored to 'p'": reg_$[[F]]<int flag> = { [-2147483648, -1], [1, 2147483647] }
// CHECK-NEXT: EVENT "Returning from 'set_null_if_flagged'": reg_$[[F]]<int flag> = { [-2147483648, -1], [1, 2147483647] }
// CHECK-NEXT: EVENT "Dereference of null pointer (loaded from variable 'p')": reg_$[[F]]<int flag> = { [-2147483648, -1], [1, 2147483647] }

// The raw plist nests the trace under the diagnostic after the path.
// RAW: <key>path</key>
// RAW: <key>constraint_trace</key>
// RAW-NEXT: <dict>
// RAW-NEXT: <key>version</key><integer>1</integer>
// RAW-NEXT: <key>steps</key>
// RAW-NEXT: <array>
// RAW-NEXT: <dict>
// RAW-NEXT: <key>path_index</key><integer>[[#]]</integer>
// RAW-NEXT: <key>symbol_ranges</key>
// RAW-NEXT: <array>
// RAW-NEXT: <dict>
// RAW-NEXT: <key>symbol</key><string>reg_$[[#]]&lt;int a&gt;</string>
// RAW-NEXT: <key>range</key><string>{ [0, 0] }</string>
