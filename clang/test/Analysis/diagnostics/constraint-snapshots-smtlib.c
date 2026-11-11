// REQUIRES: z3
// RUN: rm -rf %t && mkdir %t
// RUN: %clang_analyze_cc1 -analyzer-checker=core -analyzer-output=plist-multi-file \
// RUN:   -analyzer-config emit-constraint-snapshots=true -o %t/on.plist -verify %s
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/on.plist smtlib control \
// RUN:   | FileCheck %s --implicit-check-not=MISSING --implicit-check-not=NO-SMTLIB
// RUN: %python %S/Inputs/constraint-trace-summary.py %t/on.plist smt_variables | FileCheck %s --check-prefix=VARS

// Each Path Step carries its accumulated path condition as SMT-LIB, encoded as
// the Z3 crosscheck encodes it: one symbol per analyzer symbol, named by its
// kind and ID, and one assertion per constrained symbol.
// Every control-flow piece and event has it; a missing one prints MISSING.

int dead_symbol(int *q, int dying, unsigned u) {
  if (dying == 0)
    q = 0;
  if (u > 7)
    return 0;
  return *q; // expected-warning{{Dereference of null pointer (loaded from variable 'q')}}
}

// A symbol the analyzer dropped as dead keeps its assertion. Every symbol a
// variable holds is declared, constrained or not, so a term on it parses.
// CHECK: TRACE version 2
// CHECK: EVENT "Assuming 'dying' is equal to 0": (declare-fun reg_$[[D:[0-9]+]] () (_ BitVec 32)); (declare-fun reg_$[[U:[0-9]+]] () (_ BitVec 32)); (declare-fun reg_$[[Q:[0-9]+]] () (_ BitVec 64)); (assert (= reg_$[[D]] #x00000000)){{$}}
// CHECK: EVENT "Null pointer value stored to 'q'": (declare-fun reg_$[[D]] () (_ BitVec 32)); (declare-fun reg_$[[U]] () (_ BitVec 32)); (assert (= reg_$[[D]] #x00000000)){{$}}
// CHECK: EVENT "Assuming 'u' is <= 7": (declare-fun reg_$[[D]] () (_ BitVec 32)); (declare-fun reg_$[[U]] () (_ BitVec 32)); (assert (= reg_$[[D]] #x00000000)); (assert (and (bvuge reg_$[[U]] #x00000000) (bvule reg_$[[U]] #x00000007))){{$}}
// CHECK: EVENT "Dereference of null pointer (loaded from variable 'q')": (declare-fun reg_$[[D]] () (_ BitVec 32)); (declare-fun reg_$[[U]] () (_ BitVec 32)); (assert (= reg_$[[D]] #x00000000)); (assert (and (bvuge reg_$[[U]] #x00000000) (bvule reg_$[[U]] #x00000007))){{$}}

// A path with no constraints still has SMT-LIB, which is empty. Its absence
// would mean a Clang without Z3.
int no_constraints(void) {
  int *p = 0;
  return *p; // expected-warning{{Dereference of null pointer (loaded from variable 'p')}}
}

// CHECK: TRACE version 2
// CHECK-NEXT: EVENT "'p' initialized to a null pointer value": {{$}}
// CHECK: EVENT "Dereference of null pointer (loaded from variable 'p')": {{$}}

// A variable holding a symbol maps to that symbol's term, with the signedness
// a comparison on it needs. Concrete values have no term.
// VARS: EVENT "Assuming 'dying' is equal to 0": dying = reg_$[[VD:[0-9]+]] [signed]; q = reg_$[[VQ:[0-9]+]] [unsigned]; u = reg_$[[VU:[0-9]+]] [unsigned]{{$}}
// VARS: EVENT "Null pointer value stored to 'q'": dying = reg_$[[VD]] [signed]; u = reg_$[[VU]] [unsigned]{{$}}
