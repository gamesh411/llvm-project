// RUN: clang-rcu-analyzer --mode=sections %s -- -x c 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

static void callee(void) {
  rcu_read_unlock(); // line 6
}

int f(void) {
  rcu_read_lock();  // line 10
  callee();
  return 0;
}

// CHECK: {"type":"read_section","kind":"interprocedural","confidence":"definite","function":"f"
// CHECK: "begin_line":11
// CHECK: "end_line":12


