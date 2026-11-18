// RUN: %clang_analyze_cc1 %s \
// RUN:   -Wno-conversion -Wno-tautological-constant-compare \
// RUN:   -analyzer-checker=core,apiModeling,unix.StdCLibraryFunctions,alpha.core.Conversion \
// RUN:   -verify
// RUN: %clang_analyze_cc1 %s \
// RUN:   -Wno-conversion -Wno-tautological-constant-compare \
// RUN:   -analyzer-checker=core,apiModeling,unix.StdCLibraryFunctions,alpha.core.Conversion \
// RUN:   -analyzer-config eagerly-assume=false \
// RUN:   -verify

// A loss of sign is not reported if the value is known to be non-positive only
// because the analyzer assumed a loop condition to be false: leaving a loop
// that counts up from zero bounds the count by zero. A value that is negative
// for any other reason is reported.

typedef __typeof(sizeof(int)) size_t;
typedef struct _FILE FILE;
long ftell(FILE *);
void *memcpy(void *, const void *, size_t);
void *memset(void *, int, size_t);
int read_len(void);
int try_again(void);
void log_err(const char *);
void use(size_t);

//===----------------------------------------------------------------------===//
// The bound does not come from leaving a loop: reported.
//===----------------------------------------------------------------------===//

void negative_length_not_handled(char *d, const char *s) {
  int n = read_len();
  if (n < 0)
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

void difference_tested_through_a_variable(char *d, const char *s, int len,
                                          int off) {
  int rest = len - off;
  if (rest < 0)
    log_err("offset past the end");
  memcpy(d, s, rest * sizeof(char)); // expected-warning {{Loss of sign in implicit conversion}}
}

void negated_positive_value(char *d, const char *s, int len) {
  if (len > 0) {
    int n = -len;
    memcpy(d, s, n * sizeof(char)); // expected-warning {{Loss of sign in implicit conversion}}
  }
}

// The error value of a modelled function, whether it is converted directly or
// through a variable.
void unchecked_error_return(FILE *f) {
  size_t pos = ftell(f); // expected-warning {{Loss of sign in implicit conversion}}
  use(pos);
}

void unchecked_error_return_through_a_variable(FILE *f) {
  long pos = ftell(f);
  use(pos); // expected-warning {{Loss of sign in implicit conversion}}
}

// A positivity guard that is not the condition of the loop is a test of the
// program like any other.
void guard_around_the_loop(int n, int *d, const int *s) {
  if (n > 0) {
    for (int i = 0; i < n; i++)
      d[i] = s[i];
  }
  if (n != 0)
    memcpy(d, s, n * sizeof(int)); // expected-warning {{Loss of sign in implicit conversion}}
}

// The loop goes on while the value is negative, and it is left for another
// reason.
void sign_test_keeps_the_loop_going(char *d, const char *s) {
  int n;
  do {
    n = read_len();
  } while (n < 0 && try_again());
  memcpy(d, s, n * sizeof(char)); // expected-warning {{Loss of sign in implicit conversion}}
}

//===----------------------------------------------------------------------===//
// The bound comes from leaving a loop: not reported.
//===----------------------------------------------------------------------===//

void loop_exit_and_zero_test(int n, int *d, const int *s) {
  int i;
  for (i = 0; i < n; i++)
    d[i] = s[i];
  if (n != 0)
    memcpy(d, s, n * sizeof(int)); // no-warning
}

void while_loop_exit_and_zero_test(int n, int *d, const int *s) {
  int i = 0;
  while (i < n) {
    d[i] = s[i];
    i++;
  }
  if (n != 0)
    memcpy(d, s, n * sizeof(int)); // no-warning
}

// The positivity guard is an operand of the loop condition.
void guard_in_the_loop_condition(int n, int *d, const int *s) {
  int m = n;
  while (m > 0 && s[0])
    m--;
  if (m == 0)
    return;
  memcpy(d, s, m * sizeof(int)); // no-warning
}

// A test of another variable does not change where the bound comes from.
void unrelated_test(int n, int k, int *d, const int *s) {
  int i;
  for (i = 0; i < n; i++)
    d[i] = s[i];
  if (k < 0)
    log_err("k");
  if (n != 0)
    memcpy(d, s, n * sizeof(int)); // no-warning
}

// The exits of the loops leave a single value for 'order', which the analyzer
// then loads as a constant.
void loop_exits_pin_the_value(int order, int win, int *d) {
  for (int i = order; i < win; i++)
    for (int j = 0; j <= order; j++)
      d[j] = 0;
  for (int i = 0; i < win; i++)
    d[i] = 1;
  memset(d, 0, order * sizeof(int)); // no-warning
}
