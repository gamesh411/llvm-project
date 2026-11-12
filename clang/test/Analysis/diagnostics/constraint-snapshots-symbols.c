// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core,unix.Malloc,unix.cstring.NullArg \
// RUN:   -analyzer-config widen-loops=true -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/on.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-symbols.py %t/on.plist \
// RUN:   | FileCheck %s --implicit-check-not=NO-ENTRY \
// RUN:     --implicit-check-not=UNUSED-ENTRY --implicit-check-not=UNSORTED-TABLE \
// RUN:     --implicit-check-not=NO-TYPE --implicit-check-not=UNUSED-TYPE \
// RUN:     --implicit-check-not=UNSORTED-TYPES

// With Z3 an entry also has the SMT-LIB term of its symbol.
// RUN: %if z3 %{ %python %S/Inputs/constraint-trace-symbols.py %t/on.plist smt \
// RUN:   | FileCheck %s --check-prefix=SMT %}

// With the option off there is no trace, so no table either.
// RUN: %clang_analyze_cc1 -analyzer-checker=core,unix.Malloc,unix.cstring.NullArg \
// RUN:   -analyzer-config widen-loops=true -analyzer-output=plist-multi-file \
// RUN:   -o %t/off.plist -verify %s
// RUN: FileCheck %s --check-prefix=OFF --input-file %t/off.plist
// OFF-NOT: constraint_trace
// OFF-NOT: <key>symbols</key>

typedef __typeof__(sizeof(int)) size_t;
void *malloc(size_t);
void free(void *);
int get(void);
void fill(int *);
void *memcpy(void *, const void *, size_t);

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

// A symbolic expression has no entry among the symbols, only its type among
// the expressions; its atoms do. A parameter's value has no origin, and is
// named after the parameter.
void compound(int a) {
  int *p = 0;
  if (a > 0 && get() + a == 5)
  // CHECK-NEXT: TRACE Dereference of null pointer
  // CHECK-NEXT: SYMBOL conj_$[[#]]{int, LC[[#]], S[[#]], #1} conjured call_result "get()" @constraint-snapshots-symbols.c:[[# @LINE - 2]]:16 callee get in compound frame 0{{$}}
  // CHECK-NEXT: SYMBOL reg_$[[#]]<int a> region_value name a{{$}}
  // SMT: SYMBOL reg_$[[R:[0-9]+]]<int a> region_value name a smt reg_$[[R]] [signed]{{$}}
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
// by the call, at the node the analyzer's evaluation of the call ends in, so
// it names the region the call may have changed.
void invalidated_by_a_call(void) {
  int x = 0;
  int *p = 0;
  fill(&x);
  // CHECK-NEXT: TRACE Dereference of null pointer
  // CHECK-NEXT: SYMBOL conj_$[[#]]{int, LC[[#]], S[[#]], #1} conjured invalidation "fill(&x)" @constraint-snapshots-symbols.c:[[# @LINE - 2]]:3 callee fill region x in invalidated_by_a_call frame 0{{$}}
  if (x == 3)
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// A field of an object the call may have changed is derived from the value
// that replaced the whole object. That value gets an entry of its own, though
// no list names it.
struct Pair { int first, second; };
void fill_pair(struct Pair *);

void derived_field_of_an_invalidated_object(void) {
  struct Pair s = {0, 0};
  int *p = 0;
  fill_pair(&s);
  // CHECK-NEXT: TRACE Dereference of null pointer
  // CHECK-NEXT: SYMBOL [[PARENT:conj_\$[0-9]+\{int, LC[0-9]+, S[0-9]+, #1\}]] conjured invalidation "fill_pair(&s)" @constraint-snapshots-symbols.c:[[# @LINE - 2]]:3 callee fill_pair region s in derived_field_of_an_invalidated_object frame 0{{$}}
  // CHECK-NEXT: SYMBOL derived_$[[#]]{[[PARENT]],s.second} derived parent [[PARENT]] region s.second{{$}}
  if (s.second == 3)
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// A call may change every global, so the analyzer replaces the memory space
// of globals, and a global read afterwards is derived from that value.
int counter;
void refresh(void);

void global_after_a_call(void) {
  int *p = 0;
  if (counter != 0)
    return;
  refresh();
  // CHECK-NEXT: TRACE Dereference of null pointer
  // CHECK-NEXT: SYMBOL [[GLOBALS:conj_\$[0-9]+\{int, LC[0-9]+, S[0-9]+, #1\}]] conjured invalidation "refresh()" @constraint-snapshots-symbols.c:[[# @LINE - 2]]:3 callee refresh globals in global_after_a_call frame 0{{$}}
  // CHECK-NEXT: SYMBOL derived_$[[#]]{[[GLOBALS]],counter} derived parent [[GLOBALS]] region counter{{$}}
  // CHECK-NEXT: SYMBOL reg_$[[#]]<int counter> region_value name counter{{$}}
  if (counter == 5)
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// A checker that models memcpy invalidates its destination itself, with the
// same tag the analyzer would use, but no analyzer evaluation of the call is
// on the path, so the reason is not known.
void invalidated_by_a_checker(const int *src) {
  int x = 0;
  int *p = 0;
  memcpy(&x, src, sizeof(x));
  // CHECK-NEXT: TRACE Dereference of null pointer
  // CHECK-NEXT: SYMBOL conj_$[[#]]{int, LC[[#]], S[[#]], #1} conjured other "memcpy(&x, src, sizeof (x))" @constraint-snapshots-symbols.c:[[# @LINE - 2]]:3 callee memcpy in invalidated_by_a_checker frame 0{{$}}
  // CHECK-NEXT: SYMBOL extent_$[[#]]{SymRegion{reg_$[[#]]<const int * src>}} extent{{$}}
  // CHECK-NEXT: SYMBOL reg_$[[#]]<const int * src> region_value name src{{$}}
  if (x == 3)
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// After a few passes the analyzer stops following the loop and replaces the
// function's locals, i as well as x, at the entrance of the loop's condition.
// The symbol's statement is the first one there, and the entry gives the
// loop's place.
void widened_loop(int n) {
  int x = 0;
  for (int i = 0; i < n; ++i)
    x = 1;
  // CHECK-NEXT: TRACE Dereference of null pointer
  // CHECK-NEXT: SYMBOL conj_$[[#]]{int, LC[[#]], S[[#]], #[[#]]} conjured loop_widening "i" @constraint-snapshots-symbols.c:[[# @LINE - 3]]:19 region i loop @constraint-snapshots-symbols.c:[[# @LINE - 3]]:3 in widened_loop frame 0{{$}}
  // CHECK-NEXT: SYMBOL conj_$[[#]]{int, LC[[#]], S[[#]], #[[#]]} conjured loop_widening "i" @constraint-snapshots-symbols.c:[[# @LINE - 4]]:19 region x loop @constraint-snapshots-symbols.c:[[# @LINE - 4]]:3 in widened_loop frame 0{{$}}
  // CHECK-NEXT: SYMBOL reg_$[[#]]<int n> region_value name n{{$}}
  // CHECK-NOT:  SYMBOL
  if (x == 7) {
    int *p = 0;
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
  }
}
