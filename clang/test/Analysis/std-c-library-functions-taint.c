// RUN: %clang_analyze_cc1 %s \
// RUN:   -analyzer-output=text \
// RUN:   -analyzer-checker=core \
// RUN:   -analyzer-checker=unix.Malloc \
// RUN:   -analyzer-checker=debug.ExprInspection \
// RUN:   -analyzer-checker=alpha.security.taint \
// RUN:   -analyzer-checker=alpha.unix.StdCLibraryFunctionArgs \
// RUN:   -analyzer-checker=apiModeling.StdCLibraryFunctions \
// RUN:   -analyzer-config apiModeling.StdCLibraryFunctions:ModelPOSIX=true \
// RUN:   -analyzer-config apiModeling.StdCLibraryFunctions:DisplayLoadedSummaries=true \
// RUN:   -triple x86_64-unknown-linux -verify

void clang_analyzer_eval(int);
void clang_analyzer_dump(int);
void clang_analyzer_dump_str(const char *);
void clang_analyzer_isTainted(int);
void clang_analyzer_isTainted_str(const char *);
void clang_analyzer_dumpExtent(void *);
void clang_analyzer_warnIfReached();

const unsigned char MAX_CHAR = -1;
const int EOF = -1;

int scanf(const char *restrict format, ...);
typedef __typeof(sizeof(int)) size_t;
typedef long int ssize_t;
void *malloc(size_t size);
void free(void *ptr);
int toupper(int c);

// Test if the range constraints are checked for 'toupper'.
void testSanityWithoutTaint(int x) {
  (void)toupper(x);      // no-warning
  (void)toupper(x + 42); // no-warning
  (void)toupper(1000);
  // expected-warning@-1 {{Function argument constraint is not satisfied, constraint: Range}}
  // expected-note@-2    {{Function argument constraint is not satisfied, constraint: Range}}
  // expected-note@-3    {{The 1st arg should be within the range [[-1, -1], [0, 255]]}}
}

// Test if we perfectly constrain a tainted value, then it will become a concrete value.
void testTaintedExactValue() {
  int n;
  scanf("%d", &n); // no-warning

  if (n == EOF) {
    // expected-note@-1 + {{Assuming 'n' is equal to 'EOF'}}
    // expected-note@-2 + {{Taking true branch}}
    // 'n' becomes concrete, which is no longer tainted.

    clang_analyzer_isTainted(n); // expected-warning {{NO}} expected-note {{NO}}
    clang_analyzer_dump(n);      // expected-warning {{-1 S32b}} expected-note {{-1 S32b}}
    (void)toupper(n);            // no-warning, EOF is ok
  }
}

// -----========  Testing RangeConstraint  ========-----
// Don't warn if the RangeConstraint is known to be satisfied.
void testTaintedValueIsWithinRange() {
  int n;
  scanf("%d", &n);

  if (0 <= n && n <= MAX_CHAR) {
    // expected-note@-1 + {{Assuming 'n' is >= 0}}
    // expected-note@-2 + {{Left side of '&&' is true}}
    // expected-note@-3 + {{Assuming 'n' is <= 'MAX_CHAR'}}
    // expected-note@-4 + {{Taking true branch}}

    clang_analyzer_isTainted(n); // expected-warning {{YES}} expected-note {{YES}}
    clang_analyzer_dump(n);      // expected-warning {{conj_$}} expected-note {{conj_$}}
    (void)toupper(n);            // no-warning, constrained to be safe
  }
}

// Test if the RangeConstraint might not hold, warn for tainted.
void testTaintedValueMightBeOutOfRange() {
  int n;
  scanf("%d", &n); // expected-note {{Propagated taint to the 2nd parameter}}

  if (0 <= n && n <= MAX_CHAR) {
    // expected-note@-1 + {{Assuming 'n' is >= 0}}
    // expected-note@-2 + {{Left side of '&&' is true}}
    // expected-note@-3 + {{Assuming 'n' is <= 'MAX_CHAR'}}
    // expected-note@-4 + {{Taking true branch}}

    clang_analyzer_isTainted(n + 1); // expected-warning {{YES}} expected-note {{YES}}
    clang_analyzer_dump(n + 1);      // expected-warning {{(conj_$}} expected-note {{(conj_$}}
    (void)toupper(n + 1);            // 'n+1' might be MAX_CHAR+1, which does not satisfie the precondition of 'toupper'
    // expected-warning@-1 {{Function argument constraint is not satisfied, constraint: Range; It depends on tainted value}}
    // expected-note@-2    {{Function argument constraint is not satisfied, constraint: Range; It depends on tainted value}}
    // expected-note@-3    {{The 1st arg should be within the range [[-1, -1], [0, 255]]}}
  }
}

// -----========  Testing NotNullConstraint  ========-----
// It's just a made up example, where we get a tainted pointer.
char *strdup(const char *s);
void testTaintedPointer(const char *fmt, char *buf) {
  char *ptr;
  scanf(fmt, &ptr);                  // One does not simply read a pointer - well we do.
  clang_analyzer_isTainted_str(ptr); // expected-warning {{YES}} expected-note {{YES}}
  clang_analyzer_dump_str(ptr);      // expected-warning {{&SymRegion{conj_$}} expected-note {{&SymRegion{conj_$}}

  char *copy = strdup(ptr); // 'ptr' might be null.

  clang_analyzer_isTainted_str(copy); // expected-warning {{YES}} expected-note {{YES}}
  clang_analyzer_dump_str(copy);      // expected-warning {{&SymRegion{conj_$}} expected-note {{&SymRegion{conj_$}}

  clang_analyzer_eval(ptr != copy);
  // expected-warning@-1 {{TRUE}}  expected-note@-1 {{TRUE}}  expected-note@-1 {{Assuming 'ptr' is not equal to 'copy'}}
  // expected-warning@-2 {{FALSE}} expected-note@-2 {{FALSE}} expected-note@-2 {{Assuming 'ptr' is equal to 'copy'}}
  free(copy);
}

// -----========  Testing ComparisonConstraint  ========-----
// Only ReturnValueCondition uses this, but taint related issues only checked inside check::PreCall.
// Thus, testing this is impossible.

// -----========  Testing BufferSizeConstraint  ========-----
// Testing BufferSizeConstraint, which has 3 different scenarios:

// Scenario No 1: Concrete value as the minimum buffer size.
// Extent of `buf` must be at least 26 bytes according the POSIX standard.
struct tm;
char *asctime_r(const struct tm *restrict tm, char *restrict buf);
void testTaintedExtentMightBeOutOfRange1(struct tm *tm) {
  int n;
  scanf("%d", &n); // expected-note {{Propagated taint to the 2nd parameter}}
  if (n <= 0)      // expected-note + {{Assuming 'n' is > 0}} expected-note + {{Taking false branch}}
    return;

  char *buf = malloc(n);
  // expected-warning@-1 {{Untrusted data is used to specify the buffer size}} Generic taint checker.
  // expected-note@-2    {{Untrusted data is used to specify the buffer size}} Generic taint checker.
  // expected-note@-3 {{'buf' initialized here}}

  asctime_r(tm, buf);
  // expected-warning@-1 {{Function argument constraint is not satisfied, constraint: BufferSize; It depends on tainted value}}
  // expected-note@-2    {{Function argument constraint is not satisfied, constraint: BufferSize; It depends on tainted value}}
  // expected-note@-3    {{The size of the 2nd arg should be equal to or less than the value of 26}}

  free(buf);
}

// Scenario No 2: Argument as a buffer size.
// The extent of `address` is should be equal to `address_len`.
struct sockaddr;
typedef int socklen_t;
const int SOCKET_LEN = 404;
int bind(int socket, const struct sockaddr *address, socklen_t address_len);
void testTaintedExtentMightBeOutOfRange2(int fd, struct sockaddr *my_address) {
  int my_address_len;
  scanf("%d", &my_address_len);
  // expected-note@-1 {{Value assigned to 'my_address_len'}}
  // expected-note@-2 {{Propagated taint to the 2nd parameter}}

  bind(fd, my_address, my_address_len);
  // expected-warning@-1 {{Function argument constraint is not satisfied, constraint: BufferSize; It depends on tainted value}}
  // expected-note@-2 {{Function argument constraint is not satisfied, constraint: BufferSize; It depends on tainted value}}
  // expected-note@-3 {{The size of the 2nd arg should be equal to or less than the value of the 3rd arg}}
}

// Scenario No 3: The size is computed as a multiplication of other args.
// Here, `ptr` is the buffer, and its minimum size is `size * nmemb`.
struct FILE_impl;
typedef struct FILE_impl FILE;
size_t fread(void *restrict ptr, size_t size, size_t nmemb, FILE *restrict);
void testTaintedExtentMightBeOutOfRange3(FILE *stream) {
  int count;
  scanf("%d", &count);
  // expected-note@-1 {{Value assigned to 'count'}}
  // expected-note@-2 {{Propagated taint to the 2nd parameter}}

  if (count <= 0) // expected-note + {{Assuming 'count' is > 0}} expected-note + {{Taking false branch}}
    return;

  int buffer[40]; // expected-note {{'buffer' initialized here}}
  fread(buffer, sizeof(buffer[0]), count, stream);
  // expected-warning@-1 {{Function argument constraint is not satisfied, constraint: BufferSize; It depends on tainted value}}
  // expected-note@-2 {{Function argument constraint is not satisfied, constraint: BufferSize; It depends on tainted value}}
  // expected-note@-3 {{The size of the 1st arg should be equal to or less than the value of the 2nd arg times the 3rd arg}}
}
