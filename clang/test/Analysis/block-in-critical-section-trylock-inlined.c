// RUN: %clang_analyze_cc1 \
// RUN:   -analyzer-checker=core,unix.BlockInCriticalSection,debug.ExprInspection \
// RUN:   -analyzer-output text \
// RUN:   -verify %s

// The try-lock functions are defined here, so their calls are inlined and the
// result is already known when the checker sees it.

unsigned int sleep(unsigned int seconds);
void clang_analyzer_warnIfReached(void);

enum { thrd_success = 0, thrd_busy = 1 };
typedef struct { int opaque; } mtx_t;
typedef struct { int opaque; } pthread_mutex_t;

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
  return 0;
}

int mtx_trylock(mtx_t *mutex) {
  return thrd_busy;
}

void inlined_trylock_always_succeeds(pthread_mutex_t *m) {
  if (pthread_mutex_trylock(m) != 0) // expected-note {{Entering critical section here}}
                                     // expected-note@-1 {{Taking false branch}}
    clang_analyzer_warnIfReached(); // no-warning
  sleep(1); // expected-warning {{Call to blocking function 'sleep' inside of critical section}}
            // expected-note@-1 {{Call to blocking function 'sleep' inside of critical section}}
}

void inlined_trylock_always_fails(mtx_t *m) {
  if (mtx_trylock(m) == thrd_success)
    clang_analyzer_warnIfReached(); // no-warning
  sleep(1); // no-warning
}

// A discarded result is not split on, but a known failure is still a failure.
void inlined_trylock_always_fails_discarded(mtx_t *m) {
  mtx_trylock(m);
  sleep(1); // no-warning
}
