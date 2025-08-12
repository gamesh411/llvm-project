// RUN: clang-rcu-analyzer --mode=points %s -- -x c 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

static void callee(void) {
  rcu_read_lock();   // line 8
  rcu_read_unlock(); // line 9
}

int f(int x) {
  if (x > 0) {
    callee();
  } else {
    callee();
  }
  return x;
}

// CHECK: "possibly_dominates"
// CHECK-DAG: {"text":"x > 0","value":true
// CHECK-DAG: {"text":"x > 0","value":false
// CHECK: "definitely_dominates"
// CHECK: "possibly_dominates"
// CHECK-DAG: {"text":"x > 0","value":true
// CHECK-DAG: {"text":"x > 0","value":false
// CHECK: "definitely_dominates"


