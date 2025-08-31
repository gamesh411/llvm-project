// RUN: %clang_analyze_cc1 -analyzer-checker=alpha.unix.EmbeddedDSLMonitor \
// RUN:   -verify %s

void *malloc(unsigned long);
void free(void *);

void ok_exactly_once() {
  void *p = malloc(16);
  if (!p)
    return; // expected-warning{{resource not destroyed (violates exactly-once)}}
  free(p); // no-warning
}

void leak_missing_free() {
  void *p = malloc(32);
  return;  // expected-warning{{resource not destroyed (violates exactly-once)}}
}

void double_free(int a) {
  void *p = malloc(8);
  free(p);
  free(p); // expected-warning{{resource destroyed twice (violates exactly-once)}}
}