// RUN: %clang_analyze_cc1 -std=c++14 -analyzer-checker=core,debug.ExprInspection -verify %s

// This test verifies that the analyzer does not incorrectly assume zero
// for fields with in-class (default member) initializers when accessing
// elements of a struct array.

void clang_analyzer_warnIfReached(void);

struct S {
  int a = 3;
};

// Non-const array in main: the analyzer must not assume zero for 'a',
// because it has a default member initializer.
S sarr_nonconst[2] = {};

int main(int argc, char **argv) {
  // FIXME: Should recognize that it is 3 (from the default member initializer).
  if (sarr_nonconst[0].a == 3) {
    clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  } else {
    clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  }
}

// Const array in non-main: the analyzer resolves the default member
// initializer correctly through the lazy binding path.
const S sarr_const[2] = {};

void use_const(void) {
  if (sarr_const[0].a == 3) {
    clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  } else {
    clang_analyzer_warnIfReached(); // unreachable
  }
}
