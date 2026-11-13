// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core \
// RUN:   -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/on.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-symbols.py %t/on.plist types \
// RUN:   | FileCheck %s --implicit-check-not=NO-ENTRY \
// RUN:     --implicit-check-not=UNUSED-ENTRY --implicit-check-not=UNSORTED-TABLE \
// RUN:     --implicit-check-not=NO-TYPE --implicit-check-not=UNUSED-TYPE \
// RUN:     --implicit-check-not=UNSORTED-TYPES

// With the option off there is no trace, so no names or expressions either.
// RUN: %clang_analyze_cc1 -analyzer-checker=core \
// RUN:   -analyzer-output=plist-multi-file -o %t/off.plist -verify %s
// RUN: FileCheck %s --check-prefix=OFF --input-file %t/off.plist
// OFF-NOT: constraint_trace
// OFF-NOT: <key>expressions</key>

// The initial value of memory is named by the expression a reader would write
// for that memory, as far as the analyzer can describe it.

struct Inner { int len; };
struct Outer { Inner in; int count; Outer *next; int cells[4]; };

void fields(Outer o) {
  int *p = 0;
  if (o.count == 1 && o.in.len == 2 && o.cells[3] == 4)
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: SYMBOL reg_$[[#]]<int o.count> region_value name o.count type int{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<int o.in.len> region_value name o.in.len type int{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<int Element{o.cells,3 S64b,int}> region_value name o.cells[3] type int{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

void pointees(int *q, Outer *op) {
  int *p = 0;
  if (*q == 1 && op->in.len == 2 && op->next->count == 3 && q[2] == 4)
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: SYMBOL reg_$[[#]]<int * q> region_value name q type int * pointer{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<int Element{SymRegion{reg_$[[#]]<int * q>},0 S64b,int}> region_value name *q type int{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<int Element{SymRegion{reg_$[[#]]<int * q>},2 S64b,int}> region_value name q[2] type int{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<int Element{SymRegion{reg_$[[#]]<Outer * op>},0 S64b,struct Outer}.in.len> region_value name op->in.len type int{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<Outer * Element{SymRegion{reg_$[[#]]<Outer * op>},0 S64b,struct Outer}.next> region_value name op->next type Outer * pointer{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<int Element{SymRegion{reg_$[[#]]<Outer * Element{SymRegion{reg_$[[#]]<Outer * op>},0 S64b,struct Outer}.next>},0 S64b,struct Outer}.count> region_value name op->next->count type int{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// Memory read as another type than the pointer's is named through a cast.
void reinterpreted(void *data) {
  int *p = 0;
  if (((Inner *)data)->len == 5)
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: SYMBOL reg_$[[#]]<int Element{SymRegion{reg_$[[#]]<void * data>},0 S64b,struct Inner}.len> region_value name ((Inner *)data)->len type int{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

struct Parser {
  int *Current;
  int Depth;
  void advance();
  void parse() {
    int *p = 0;
    if (Depth == 3 && Current) {
      advance();
      if (!Current)
        *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
    }
  }
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: SYMBOL reg_$[[#]]<int Element{SymRegion{reg_$[[#]]<struct Parser * this>},0 S64b,struct Parser}.Depth> region_value name this->Depth type int{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<int * Element{SymRegion{reg_$[[#]]<struct Parser * this>},0 S64b,struct Parser}.Current> region_value name this->Current type int * pointer{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<struct Parser * this> region_value name this type Parser * pointer{{$}}

  // A value a call replaced is a part of what the call may have changed, and
  // both are named the same way.
  // CHECK-DAG: SYMBOL derived_$[[#]]{conj_$[[#]]{{{.*}}},Element{SymRegion{reg_$[[#]]<struct Parser * this>},0 S64b,struct Parser}.Current} derived parent conj_$[[#]]{{{.*}}} region this->Current type int * pointer{{$}}
  // CHECK-DAG: SYMBOL conj_$[[#]]{{{.*}}} conjured invalidation "this->advance()" {{.*}} region *this in Parser::parse frame 0 type int{{$}}
};

// Memory the analyzer cannot describe, such as the pointee of a call's
// result, has no name.
Outer *get();
void unnamed() {
  int *p = 0;
  if (get()->count == 7)
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: SYMBOL reg_$[[#]]<int Element{SymRegion{conj_$[[#]]{{{.*}}}},0 S64b,struct Outer}.count> region_value type int{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// Memory of a call, such as the callee's `this` when the analyzer lost the
// object's address, is spelled as the analyzed function's own, and two calls'
// alike, so it has no name, and says that it belongs to a call.
struct Use {
  int *Val;
  int *get() const { return Val; }
};
struct User {
  unsigned N;
  Use *ops() { return reinterpret_cast<Use *>(this) - N; }
};
long same(long x) { return x; }
void callFrames(User *U, long y) {
  int *p = 0;
  int *a = U->ops()[0].get();
  int *b = U->ops()[1].get();
  long v = (long)&y;
  if (a && !b && same(v * 3) == 5)
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: SYMBOL reg_$[[#]]<User * U> region_value name U type User * pointer{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<const struct Use * this> region_value in_call type const Use * pointer{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<int * Element{SymRegion{reg_$[[#]]<const struct Use * this>},0 S64b,struct Use}.Val> region_value in_call type int * pointer{{$}}
  // CHECK-DAG: SYMBOL reg_$[[#]]<long x> region_value in_call type long{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// A construction the source does not spell, such as converting an argument,
// reads as the class it constructs, and a field of the temporary it made
// keeps the end of its access path although the temporary has no name.
struct Point {
  int *Block;
  Point(int *B);
};
int *readBlock(const Point &P) { return P.Block; }
void temporaries(int *B) {
  int *p = 0;
  if (!readBlock(B))
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: SYMBOL conj_$[[#]]{{{.*}}} conjured invalidation "Point(B)" {{.*}} callee Point in temporaries frame 0 type int{{$}}
  // CHECK-DAG: SYMBOL derived_$[[#]]{conj_$[[#]]{{{.*}}},temp_object{const Point, S{{[0-9]+}}}.Block} derived parent conj_$[[#]]{{{.*}}} member .Block type int * pointer{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// The end of an access path goes through pointers that are fields of memory
// with no description.
struct Node { Node *next; int count; };
Node *head();
void reset(Node *);
void behindCall() {
  int *p = 0;
  Node *n = head();
  reset(n);
  if (n->next->count == 3)
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: SYMBOL derived_$[[#]]{conj_$[[#]]{{{.*}}},Element{SymRegion{conj_$[[#]]{{{.*}}}},0 S64b,struct Node}.next} derived parent conj_$[[#]]{{{.*}}} member ->next type Node * pointer{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// A symbolic expression has the type of its value, which no atom says.
void expressions(unsigned long mask, int a, int b) {
  int *p = 0;
  if ((mask & 7) != 0 && a + b > 3)
  // CHECK:     TRACE Dereference of null pointer
  // CHECK-DAG: EXPRESSION (reg_$[[#]]<unsigned long mask>) & 7U type unsigned long{{$}}
  // CHECK-DAG: EXPRESSION (reg_$[[#]]<int a>) + (reg_$[[#]]<int b>) type int{{$}}
    *p = 1; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}
