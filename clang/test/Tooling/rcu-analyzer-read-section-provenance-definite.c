// RUN: clang-rcu-analyzer --mode=sections %s -- -x c 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

static void callee(void) {
  rcu_read_unlock(); // line 6
}

int f(void) {
  rcu_read_lock();  // line 10
  callee();         // line 11
  return 0;
}

// CHECK: {"type":"read_section","kind":"interprocedural","confidence":"definite","function":"f"
// CHECK: "begin_line":11
// CHECK: "end_line":12
// CHECK: "closed_by":"callee"
// CHECK-SAME: "line":7
// CHECK-DAG: "function":"f","file":"{{.*}}","line":12,"col":{{[0-9]+}}
// CHECK-DAG: "function":"callee","file":"{{.*}}","line":7,"col":{{[0-9]+}}


