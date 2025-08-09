// RUN: clang-rcu-analyzer --mode=points %s -- -x c 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

int f(int a) {
  if (a > 0) {
    rcu_read_lock();
  } else {
    rcu_read_lock();
  }
  return 0;
}

// First lock under then-branch
// CHECK: {"type":"call","name":"rcu_read_lock","function":"f","file":"
// CHECK-SAME: ,"line":8
// CHECK-SAME: ,"dominators":[
// CHECK-SAME: {"text":"a > 0","value":true,"file":"{{.*}}","line":7

// Second lock under else-branch
// CHECK: {"type":"call","name":"rcu_read_lock","function":"f","file":"
// CHECK-SAME: ,"line":10
// CHECK-SAME: ,"dominators":[
// CHECK-SAME: {"text":"a > 0","value":false,"file":"{{.*}}","line":7


