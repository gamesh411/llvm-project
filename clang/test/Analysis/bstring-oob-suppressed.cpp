// RUN: %clang_analyze_cc1 \
// RUN:     -analyzer-checker=core \
// RUN:     -analyzer-checker=unix.cstring \
// RUN:     -analyzer-checker=unix.Malloc \
// RUN:     -analyzer-checker=debug.ExprInspection \
// RUN:     -analyzer-config eagerly-assume=false \
// RUN:     -analyzer-checker=alpha.unix.cstring.BufferOverlap \
// RUN:     -analyzer-checker=unix.cstring.NotNullTerminated \
// RUN:     -verify %s

// These tests exercise memset calls that go out-of-bounds. They are separated
// from bstring.cpp because they require OutOfBounds to be disabled: with
// OutOfBounds enabled, the analysis sinks at the OOB memset and the subsequent
// clang_analyzer_eval calls are not reached.
//
// FIXME: These tests document the analyzer's current behavior when OutOfBounds
// is disabled and OOB memset calls don't terminate the path. Once the
// OutOfBounds checker is stable enough to always terminate execution at OOB
// errors (regardless of whether the checker frontend is enabled), these tests
// should be revisited: the clang_analyzer_eval calls after the OOB memset
// would become unreachable.

#include "Inputs/system-header-simulator-cxx.h"

void clang_analyzer_eval(int);
void *memset(void *dest, int ch, std::size_t count);

namespace memset_non_pod {
class Base {
public:
  int b_mem;
  Base() : b_mem(1) {}
};

class Derived : public Base {
public:
  int d_mem;
  Derived() : d_mem(2) {}
};

void memset2_inheritance_field() {
  Derived d;
  // FIXME: OOB memset on a derived field with sizeof(Derived).
  // Current behavior: the not-set part is treated as UNKNOWN.
  memset(&d.d_mem, 0, sizeof(Derived));
  clang_analyzer_eval(d.b_mem == 0); // expected-warning{{UNKNOWN}}
  clang_analyzer_eval(d.d_mem == 0); // expected-warning{{UNKNOWN}}
}

void memset3_inheritance_field() {
  Derived d;
  // FIXME: memset on the base field with sizeof(Derived). This doesn't
  // actually write past the object's extent, but it's UB because the memset
  // accesses the object through a pointer to a member, violating aliasing
  // rules. Current behavior: the field is treated as correctly set to 0.
  memset(&d.b_mem, 0, sizeof(Derived));
  clang_analyzer_eval(d.b_mem == 0); // expected-warning{{TRUE}}
  clang_analyzer_eval(d.d_mem == 0); // expected-warning{{TRUE}}
}

class BaseVirtual {
public:
  int b_mem;
  virtual int get() { return 1; }
};

class DerivedVirtual : public BaseVirtual {
public:
  int d_mem;
};

void memset8_virtual_inheritance_field() {
  DerivedVirtual d;
  // FIXME: Same as memset3, but the base has a virtual function. In typical
  // implementations &d.b_mem differs from &d because the vtable pointer
  // precedes the first member, so this may also write past the object's
  // extent.
  memset(&d.b_mem, 0, sizeof(Derived));
  clang_analyzer_eval(d.b_mem == 0); // expected-warning{{UNKNOWN}}
  clang_analyzer_eval(d.d_mem == 0); // expected-warning{{UNKNOWN}}
}
} // namespace memset_non_pod

void memset1_new_array() {
  int *array = new int[10];
  memset(array, 0, 10 * sizeof(int));
  clang_analyzer_eval(array[2] == 0); // expected-warning{{TRUE}}
  // FIXME: OOB memset on a heap array. The analysis continues past it.
  memset(array + 1, 'a', 10 * sizeof(9));
  clang_analyzer_eval(array[2] == 0); // expected-warning{{UNKNOWN}}
  delete[] array;
}
