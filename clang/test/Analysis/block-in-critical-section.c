// RUN: %clang_analyze_cc1 \
// RUN:   -analyzer-checker=core,unix.BlockInCriticalSection,debug.ExprInspection \
// RUN:   -analyzer-output text \
// RUN:   -DTHRD_SUCCESS=0 \
// RUN:   -verify %s
// RUN: %clang_analyze_cc1 \
// RUN:   -analyzer-checker=core,unix.BlockInCriticalSection,debug.ExprInspection \
// RUN:   -analyzer-output text \
// RUN:   -DTHRD_SUCCESS=4 \
// RUN:   -verify %s
// RUN: %clang_analyze_cc1 \
// RUN:   -analyzer-checker=core,unix.BlockInCriticalSection,debug.ExprInspection \
// RUN:   -analyzer-output text \
// RUN:   -DTHRD_SUCCESS_IS_MACRO \
// RUN:   -verify %s

// This should not crash
int (*a)(void);
void b(void) { a(); }

unsigned int sleep(unsigned int seconds);
void clang_analyzer_warnIfReached(void);

// Implementations disagree on the value of thrd_success, so the RUN lines set
// it. TinyCThread defines it as a macro.
#ifdef THRD_SUCCESS_IS_MACRO
#define thrd_success 1
#else
enum { thrd_success = THRD_SUCCESS };
#endif
typedef struct { int opaque; } mtx_t;
struct timespec;
int mtx_trylock(mtx_t *mutex);
int mtx_timedlock(mtx_t *mutex, const struct timespec *time_point);
int mtx_unlock(mtx_t *mutex);

void c11_trylock(mtx_t *m) {
  if (mtx_trylock(m) == thrd_success) { // expected-note {{Assuming the lock is acquired; entering critical section here}}
                                        // expected-note@-1 {{Taking true branch}}
                                        // expected-note@-2 {{Taking false branch}}
    sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
              // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
    mtx_unlock(m);
  } else {
    clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
                                    // expected-note@-1 {{REACHABLE}}
    sleep(1); // no-warning
  }
}

void c11_timedlock(mtx_t *m, const struct timespec *t) {
  if (mtx_timedlock(m, t) == thrd_success) { // expected-note {{Assuming the lock is acquired; entering critical section here}}
                                             // expected-note@-1 {{Taking true branch}}
                                             // expected-note@-2 {{Taking false branch}}
    sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
              // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
    mtx_unlock(m);
  } else {
    clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
                                    // expected-note@-1 {{REACHABLE}}
    sleep(1); // no-warning
  }
}
