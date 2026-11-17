// RUN: %clang_analyze_cc1 %s \
// RUN:   -Wno-conversion -Wno-tautological-constant-compare \
// RUN:   -analyzer-checker=core,apiModeling,unix.StdCLibraryFunctions,alpha.core.Conversion \
// RUN:   -verify

// A loss of sign is reported only if the negative value is backed by evidence
// on the path: the code compares the value against a non-positive constant,
// tests it for equality with a negative constant, or compares the operands of
// a difference. A value that is negative only because the analyzer took the
// exit of a loop or split "<= 0" with "!= 0" must not be reported.

typedef __typeof(sizeof(int)) size_t;
void *memcpy(void *, const void *, size_t);
void *malloc(size_t);
int read_len(void);
void log_err(const char *);

//===----------------------------------------------------------------------===//
// The program tests the sign itself: these are reported.
//===----------------------------------------------------------------------===//

void negative_length_not_handled(char *d, const char *s) {
  int n = read_len();
  if (n < 0)
    log_err("bad length");
  memcpy(d, s, n * sizeof(int)); // expected-warning {{Loss of sign in implicit conversion}}
}

int *negative_count_to_allocation(void) {
  int n = read_len();
  if (n < 0)
    log_err("bad length");
  return malloc(sizeof(int) * n); // expected-warning {{Loss of sign in implicit conversion}}
}

void non_strict_test_after_zero_test(int n, int *d, const int *s) {
  if (n == 0)
    return;
  if (n <= 0)
    log_err("bad length");
  memcpy(d, s, n * sizeof(int)); // expected-warning {{Loss of sign in implicit conversion}}
}

void error_value_not_handled(int *d, const int *s) {
  int n = read_len();
  if (n == -1)
    log_err("end of input");
  memcpy(d, s, n * sizeof(int)); // expected-warning {{Loss of sign in implicit conversion}}
}

void constant_negative_length(int *d, const int *s) {
  int n = -1;
  memcpy(d, s, n * sizeof(int)); // expected-warning {{Loss of sign in implicit conversion}}
}

void non_negative_test_else_branch(int *d, const int *s) {
  int n = read_len();
  if (n >= 0) {
    d[0] = s[0];
  } else {
    memcpy(d, s, n * sizeof(int)); // expected-warning {{Loss of sign in implicit conversion}}
  }
}

void difference_tested_through_a_variable(char *d, const char *s, int len,
                                          int off) {
  int rest = len - off;
  if (rest < 0)
    log_err("offset past the end");
  memcpy(d, s, rest * sizeof(char)); // expected-warning {{Loss of sign in implicit conversion}}
}

void test_far_from_use(int *d, const int *s) {
  int n = read_len();
  if (n < 0)
    log_err("bad length");
  d[0] = s[0];
  d[1] = s[1];
  memcpy(d, s, n * sizeof(int)); // expected-warning {{Loss of sign in implicit conversion}}
}

// The tested operand makes the negated value negative.
void negated_positive_value(char *d, const char *s, int len) {
  if (len > 0) {
    int n = -len;
    memcpy(d, s, n * sizeof(char)); // expected-warning {{Loss of sign in implicit conversion}}
  }
}

//===----------------------------------------------------------------------===//
// Negative only because of the analysis: not reported.
//===----------------------------------------------------------------------===//

// The positivity guard of a loop is false, and then the zero test is false.
void guard_complement_and_zero_split(int n, int *d, const int *s) {
  int m = n;
  while (m > 0 && s[0])
    m--;
  if (m == 0)
    return;
  memcpy(d, s, m * sizeof(int)); // no-warning
}

// The loop did not run, and then the count is known to be nonzero.
void loop_exit_and_zero_test(int n, int *d, const int *s) {
  int i;
  for (i = 0; i < n; i++)
    d[i] = s[i];
  if (n != 0)
    memcpy(d, s, n * sizeof(int)); // no-warning
}

// A test of another variable does not make the count's sign a tested one.
void unrelated_test(int n, int k, int *d, const int *s) {
  int i;
  for (i = 0; i < n; i++)
    d[i] = s[i];
  if (k < 0)
    log_err("k");
  if (n != 0)
    memcpy(d, s, n * sizeof(int)); // no-warning
}
