// RUN: clang-rcu-analyzer --mode=sections %s -- -x c 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

static void maybe_unlock(int k) {
  if (k) rcu_read_unlock();
}

int g(int k) {
  rcu_read_lock();  // line 10
  maybe_unlock(k);
  return 0;
}

// CHECK: {"type":"read_section","kind":"interprocedural","confidence":"probable","function":"g"
// CHECK: "begin_line":11
// CHECK: "end_line":12


