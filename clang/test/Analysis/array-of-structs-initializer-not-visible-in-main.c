// RUN: %clang_analyze_cc1 -analyzer-checker=core,debug.ExprInspection -verify %s

// This test verifies that the analyzer can 'see' the initializer of an
// array of structs, covering const, non-const, and main() vs non-main cases.

void clang_analyzer_warnIfReached(void);

struct S {
  int a;
};

// Non-const struct array: initializer should be visible in main().
struct S struct_array[1] = {
  {11},
};

int main(int argc, char **argv) {
  if (struct_array->a == 11) {
    clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  } else {
    clang_analyzer_warnIfReached(); // unreachable
  }
}

// Const struct array: initializer should be visible in any function.
const struct S struct_array_const[1] = { {44} };

void use_struct_array_const(void) {
  if (struct_array_const->a == 44) {
    clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  } else {
    clang_analyzer_warnIfReached(); // unreachable
  }
}

// Non-const struct array in non-main: initializer must NOT be trusted.
struct S struct_array_nonconst[1] = { {55} };

void use_struct_array_nonconst(void) {
  if (struct_array_nonconst->a == 55) {
    clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  } else {
    // This is intentionally reachable, because this is a non-const array which
    // may have been changed before the call to this function.
    clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  }
}
