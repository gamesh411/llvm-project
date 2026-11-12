// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/on.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-cfg.py %t/on.plist \
// RUN:   | FileCheck %s --implicit-check-not=NO-POSITION

// With the option off there is no trace, so no graphs either.
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -o %t/off.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-cfg.py %t/off.plist | FileCheck %s --check-prefix=OFF

// OFF-COUNT-4: NO-CFGS
// OFF-NOT: CFG

// Each function on the Bug Path carries its control flow graph once per
// report, and every Path Step says where in it it is.

int branch(int *p, int a) {
  if (a == 0)
    p = 0;
  return *p; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// Blocks come entry first, elements as debug.DumpCFG lists them. A parent
// marks a linearized subexpression of a statement in the same block.
// CHECK:      CFG branch entry B4 exit B0
// CHECK-NEXT: B4 path -> B3
// CHECK-NEXT: B3 path: 1: a @19 ^2; 2: a (ImplicitCastExpr, LValueToRValue, int) @19 ^4; 3: 0 @19 ^4; 4: a == 0 @19; T: if a == 0 -> B2 B1
// CHECK-NEXT: B2 path: 1: 0 @20 ^2; 2: 0 (ImplicitCastExpr, NullToPointer, int *) @20 ^4; 3: p @20 ^4; 4: p = 0 @20 -> B1
// CHECK-NEXT: B1 path: 1: p @21 ^2; 2: p (ImplicitCastExpr, LValueToRValue, int *) @21 ^3; 3: *p @21 ^4; 4: *p (ImplicitCastExpr, LValueToRValue, int) @21 ^5; 5: return *p; @21 -> B0
// CHECK-NEXT: B0{{$}}
// CHECK-NEXT: EDGES B2->B1 B3->B2 B4->B3{{$}}

// A step sits at the element its node evaluated, which is the condition for
// this assumption, and the edge into a line ends where its event is.
// CHECK: CONTROL ending at 19:7: branch B3.4
// CHECK: EVENT "Assuming 'a' is equal to 0": branch B3.4
// CHECK: CONTROL ending at 20:5: branch B2.4
// CHECK: EVENT "Null pointer value stored to 'p'": branch B2.4
// CHECK: EVENT "Dereference of null pointer (loaded from variable 'p')": branch B1.4

static void set_null(int **pp, int flag) {
  if (flag)
    *pp = 0;
}

int call(int *p, int flag) {
  set_null(&p, flag);
  return *p; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// The caller comes first, since it is where the Bug Path starts. The callee's
// exit is on the path, the caller's is not.
// CHECK:      CFG call entry B2 exit B0 body 1
// CHECK-NEXT: B2 path -> B1
// CHECK-NEXT: B1 path: {{.*}} -> B0
// CHECK-NEXT: B0{{$}}
// CHECK-NEXT: EDGES B2->B1{{$}}
// CHECK-NEXT: CFG set_null entry B3 exit B0 body 2
// CHECK-NEXT: B3 path -> B2
// CHECK-NEXT: B2 path: {{.*}}; T: if flag -> B1 B0
// CHECK-NEXT: B1 path: {{.*}} -> B0
// CHECK-NEXT: B0 path{{$}}
// CHECK-NEXT: EDGES B1->B0 B2->B1 B3->B2{{$}}

// A call's events sit at the call in the caller. This assumption was made on
// the branch edge, so it sits at the terminator.
// CHECK:      EVENT "Calling 'set_null'": call B1.7
// CHECK:      EVENT "Assuming 'flag' is not equal to 0": set_null B2.T
// CHECK:      EVENT "Null pointer value stored to 'p'": set_null B1.6
// CHECK:      EVENT "Returning from 'set_null'": call B1.7

int call_again(int *q, int flag) {
  set_null(&q, flag);
  return *q; // expected-warning{{Dereference of null pointer (loaded from variable 'q')}}
}

// A graph's body is kept once per file, since it does not depend on the
// path, so this report names the body of set_null that the one through `call`
// does, with its own path.
// CHECK:      CFG call_again entry B2 exit B0 body 3
// CHECK-NEXT: B2 path -> B1
// CHECK:      CFG set_null entry B3 exit B0 body 2
// CHECK-NEXT: B3 path -> B2
// CHECK-NEXT: B2 path: {{.*}}; T: if flag -> B1 B0
// CHECK:      EDGES B1->B0 B2->B1 B3->B2{{$}}
// CHECK:      EVENT "Calling 'set_null'": call_again B1.7

int loop(int *p) {
  for (int i = 0; i < 3; ++i)
    if (i == 2)
      p = 0;
  return *p; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// Every iteration passes the same blocks, so each is listed once, and the
// steps of each iteration point at the same places. Going back to the loop
// head is a fall-through edge, so it only enters the head's block.
// CHECK:      CFG loop entry B7 exit B0
// CHECK:      B5 path: {{.*}}; T: for (...; i < 3; ...) -> B4 B1
// CHECK:      EDGES B2->B5 B3->B2 B4->B2 B4->B3 B5->B1 B5->B4 B6->B5 B7->B6{{$}}
// CHECK-COUNT-2: EVENT "Looping back to the head of the loop": loop B5{{$}}
// CHECK:      EVENT "Entering loop body": loop B5.T
// CHECK:      CONTROL ending at [[@LINE-13]]:9: loop B4.T
// CHECK:      EVENT "Null pointer value stored to 'p'": loop B3.4

// The five functions on the four Bug Paths.
// CHECK:      BODIES 5
// OFF:        BODIES 0
