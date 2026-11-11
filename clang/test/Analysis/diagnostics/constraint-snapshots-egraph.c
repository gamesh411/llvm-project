// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/on.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-egraph.py %t/on.plist \
// RUN:   | FileCheck %s --implicit-check-not=NO-NODE --implicit-check-not=BAD-TABLE

// With the option off there is no trace, so no nodes either.
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -o %t/off.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-egraph.py %t/off.plist | FileCheck %s --check-prefix=OFF

// OFF-COUNT-2: NO-NODES
// OFF-NOT: N{{[0-9]}}

// Every Path Step names the analyzer node its snapshot came from, with that
// node's calling context and location, so one statement reached through
// several calls reads as several states.

static int take(int **pp, int flag) {
  if (flag) {
    *pp = 0;
    return 0;
  }
  return **pp; // expected-warning{{Dereference of null pointer}}
}

int contexts(int *p, int a, int b) {
  take(&p, a);
  return take(&p, b);
}

// Only the nodes steps came from are listed. A call's two events share the
// call's node, which is in the caller. The same `if` in the callee then reads
// as two states, told apart by the call sites of their frames, and the edges
// into a line share the node of the event there.
// CHECK:      NODES 9 FRAMES 3 SHARED-IDS 0
// CHECK-NEXT: EVENT "Calling 'take'": N0 CallEnter @constraint-snapshots-egraph.c:28:3 in contexts{{$}}
// CHECK-NEXT: EVENT "Entered call from 'contexts'": N0 CallEnter @constraint-snapshots-egraph.c:28:3 in contexts{{$}}
// CHECK:      EVENT "Assuming 'flag' is not equal to 0": N1 BlockEdge @constraint-snapshots-egraph.c:20:3 in take called @constraint-snapshots-egraph.c:28:3 <- contexts{{$}}
// CHECK:      EVENT "Null pointer value stored to 'p'": N2 PostStore @constraint-snapshots-egraph.c:21:5 in take called @constraint-snapshots-egraph.c:28:3 <- contexts{{$}}
// CHECK:      EVENT "Returning from 'take'": N5 CallExitEnd @constraint-snapshots-egraph.c:28:3 in contexts{{$}}
// CHECK:      EVENT "Calling 'take'": N6 CallEnter @constraint-snapshots-egraph.c:29:10 in contexts{{$}}
// CHECK:      CONTROL ending at 20:7: N7 BlockEdge @constraint-snapshots-egraph.c:20:3 in take called @constraint-snapshots-egraph.c:29:10 <- contexts{{$}}
// CHECK-NEXT: EVENT "Assuming 'flag' is 0": N7 BlockEdge @constraint-snapshots-egraph.c:20:3 in take called @constraint-snapshots-egraph.c:29:10 <- contexts{{$}}
// CHECK:      EVENT "Dereference of null pointer": N8 PreLoad @constraint-snapshots-egraph.c:24:10 in take called @constraint-snapshots-egraph.c:29:10 <- contexts{{$}}

int branch(int *p, int a) {
  if (a == 0)
    p = 0;
  return *p; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// A path that stays in one function has one frame, and the edge into the
// condition shares the node of the assumption made there.
// CHECK:      NODES 4 FRAMES 1 SHARED-IDS 0
// CHECK-NEXT: CONTROL ending at 48:7: N0 PostStmt @constraint-snapshots-egraph.c:48:7 in branch{{$}}
// CHECK-NEXT: EVENT "Assuming 'a' is equal to 0": N0 PostStmt @constraint-snapshots-egraph.c:48:7 in branch{{$}}
// CHECK:      EVENT "Dereference of null pointer (loaded from variable 'p')": N3 PreLoad @constraint-snapshots-egraph.c:50:10 in branch{{$}}

// The exploded graph gives the newest node's ID out again after it reclaims a
// node, so on a long path two nodes can share an ID. Each still has its own
// entry, so a step does not show another node's state.
// RUN: %python %S/Inputs/constraint-trace-long-path.py 300 > %t/long.c
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/long.plist %t/long.c 2>/dev/null
// RUN: %python %S/Inputs/constraint-trace-egraph.py %t/long.plist \
// RUN:   | FileCheck %s --check-prefix=LONG --implicit-check-not=NO-NODE --implicit-check-not=BAD-TABLE
// LONG: NODES {{[0-9]+}} FRAMES 1 SHARED-IDS {{[1-9][0-9]*}}{{$}}
