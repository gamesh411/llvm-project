// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core,unix.Malloc \
// RUN:   -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/on.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-symbols.py %t/on.plist \
// RUN:   | FileCheck %s --implicit-check-not=NO-ENTRY \
// RUN:     --implicit-check-not=UNUSED-ENTRY --implicit-check-not=UNSORTED-TABLE

// With Z3 an entry also has the SMT-LIB term of its symbol.
// RUN: %if z3 %{ %python %S/Inputs/constraint-trace-symbols.py %t/on.plist smt \
// RUN:   | FileCheck %s --check-prefix=SMT %}

// With the option off there is no trace, so no table either.
// RUN: %clang_analyze_cc1 -analyzer-checker=core,unix.Malloc \
// RUN:   -analyzer-output=plist-multi-file -o %t/off.plist -verify %s
// RUN: FileCheck %s --check-prefix=OFF --input-file %t/off.plist
// OFF-NOT: constraint_trace
// OFF-NOT: <key>symbols</key>

typedef __typeof__(sizeof(int)) size_t;
void *malloc(size_t);
void free(void *);
int get(void);
void fill(int *);

// The analyzer evaluates get() without seeing inside it, so the value it
// returns is a call result, named by its callee and made in this frame.
void call_result(void) {
  int *p = 0;
  if (get() == 42)
  // CHECK:      TRACE Dereference of null pointer
  // CHECK-NEXT: SYMBOL conj_$[[#]]{int, LC[[#]], S[[#]], #1} conjured call_result "get()" @constraint-snapshots-symbols.c:[[# @LINE - 2]]:7 callee get in call_result frame 0{{$}}
  // SMT: SYMBOL conj_$[[C:[0-9]+]]{int, {{.*}} in call_result frame 0 smt conj_$[[C]] [signed]{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// A symbolic expression has no entry of its own; its atoms do. A parameter's
// value has no origin.
void compound(int a) {
  int *p = 0;
  if (a > 0 && get() + a == 5)
  // CHECK-NEXT: TRACE Dereference of null pointer
  // CHECK-NEXT: SYMBOL conj_$[[#]]{int, LC[[#]], S[[#]], #1} conjured call_result "get()" @constraint-snapshots-symbols.c:[[# @LINE - 2]]:16 callee get in compound frame 0{{$}}
  // CHECK-NEXT: SYMBOL reg_$[[#]]<int a> region_value{{$}}
  // SMT: SYMBOL reg_$[[R:[0-9]+]]<int a> region_value smt reg_$[[R]] [signed]{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// The call is made in a callee the diagnostic leaves out, so its frame is not
// among the trace's stack frames, and the entry names the function instead.
static int wrap(void) { return get(); }
// CHECK-NEXT: TRACE Dereference of null pointer
// CHECK-NEXT: SYMBOL conj_$[[#]]{int, LC[[#]], S[[#]], #1} conjured call_result "get()" @constraint-snapshots-symbols.c:[[# @LINE - 2]]:32 callee get in wrap frame none{{$}}

void pruned_callee(void) {
  int *p = 0;
  if (wrap() == 7)
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// unix.Malloc models malloc itself. Its return value is made with the same
// statement, frame and tag the analyzer would use, but no analyzer evaluation
// of the call is on the path, so the reason is not known.
void modelled_by_a_checker(void) {
  int *m = malloc(4);
  // CHECK-NEXT: TRACE Dereference of null pointer
  // CHECK-NEXT: SYMBOL conj_$[[#]]{void *, LC[[#]], S[[#]], #1} conjured other "malloc(4)" @constraint-snapshots-symbols.c:[[# @LINE - 2]]:12 callee malloc in modelled_by_a_checker frame 0{{$}}
  if (!m) {
    int *p = 0;
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
  }
  free(m);
}

// The value of x after fill(&x) is conjured by invalidating x, not returned
// by the call. Clang does not classify invalidation yet, so it is "other".
void invalidated_by_a_call(void) {
  int x = 0;
  int *p = 0;
  fill(&x);
  // CHECK-NEXT: TRACE Dereference of null pointer
  // CHECK-NEXT: SYMBOL conj_$[[#]]{int, LC[[#]], S[[#]], #1} conjured other "fill(&x)" @constraint-snapshots-symbols.c:[[# @LINE - 2]]:3 callee fill in invalidated_by_a_call frame 0{{$}}
  // CHECK-NOT:  SYMBOL
  if (x == 3)
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}
