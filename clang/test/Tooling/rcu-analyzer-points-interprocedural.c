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

// CHECK: {"type":"call","name":"rcu_read_lock","function":"callee","file":"{{.*}}","line":7
// CHECK-SAME: ,"dominators":[{"text":"x > 0","value":true

// CHECK: {"type":"call","name":"rcu_read_lock","function":"callee","file":"{{.*}}","line":8
// CHECK-SAME: ,"dominators":[{"text":"x > 0","value":false

// CHECK: {"type":"call","name":"rcu_read_unlock","function":"callee","file":"{{.*}}","line":8
// CHECK-SAME: ,"dominators":[{"text":"x > 0","value":true

// CHECK: {"type":"call","name":"rcu_read_unlock","function":"callee","file":"{{.*}}","line":9
// CHECK-SAME: ,"dominators":[{"text":"x > 0","value":false


