// REQUIRES: future-mutex-checker
// RUN: not --crash echo "mutex test placeholder" >/dev/null

// Test file for demonstrating the embedded DSL framework with mutex lock/unlock property
// This shows how the framework can be used for arbitrary temporal logic properties

// Mock mutex type and functions for testing
typedef struct { int dummy; } pthread_mutex_t;

void lock(pthread_mutex_t *mutex) {}
void unlock(pthread_mutex_t *mutex) {}

void ok_lock_unlock_once() {
  pthread_mutex_t mutex;
  lock(&mutex);
  unlock(&mutex); // no-warning
} // expected-warning{{acquired lock not released (violates exactly-once)}}

void leak_missing_unlock() {
  pthread_mutex_t mutex;
  lock(&mutex);
  return;  // expected-warning{{Lock leak: acquired lock not released}}
}

void double_lock(int a) {
  pthread_mutex_t mutex;
  lock(&mutex);
  lock(&mutex); // expected-warning{{Double lock: lock acquired multiple times}}
  unlock(&mutex);
}

void double_unlock(int a) {
  pthread_mutex_t mutex;
  lock(&mutex);
  unlock(&mutex);
  unlock(&mutex); // expected-warning{{Double unlock: lock released multiple times}}
}

// Note: This test demonstrates the framework's ability to handle different
// temporal properties beyond malloc/free. The actual implementation would
// need a specialized MutexLockUnlockEventHandler, but the DSL framework
// provides the infrastructure to define arbitrary LTL formulas.
