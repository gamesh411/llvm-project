// RUN: clang-rcu-analyzer --mode=points %s -- -x c 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

int g(int a, int b) {
  // Both paths reach here; only (a > 0) dominates if the lock is inside then.
  if (a > 0) {
    rcu_read_lock();
  } else {
    if (b < 5) {
      rcu_read_lock();
    } else {
      rcu_read_unlock();
    }
    if (b > 10) {
      rcu_read_unlock();
    }
  }
  return a + b;
}

// Lock under first then-branch
// CHECK: {"type":"call","name":"rcu_read_lock","function":"g","file":"
// CHECK-SAME: ,"line":9
// CHECK-SAME: ,"dominators":[
// CHECK-SAME: {"text":"a > 0","value":true,"file":"{{.*}}","line":8

// Lock under first else and second then-branch
// CHECK: {"type":"call","name":"rcu_read_lock","function":"g","file":"
// CHECK-SAME: ,"line":12
// CHECK-SAME: ,"dominators":[
// CHECK-SAME: {"text":"a > 0","value":false,"file":"{{.*}}","line":8
// CHECK-SAME: {"text":"b < 5","value":true,"file":"{{.*}}","line":11

// Unlock under first else and second else-branch
// CHECK: {"type":"call","name":"rcu_read_unlock","function":"g","file":"
// CHECK-SAME: ,"line":14
// CHECK-SAME: ,"dominators":[
// CHECK-SAME: {"text":"a > 0","value":false,"file":"{{.*}}","line":8
// CHECK-SAME: {"text":"b < 5","value":false,"file":"{{.*}}","line":11

// Unlock under else-branch and second then-branch
// CHECK: {"type":"call","name":"rcu_read_unlock","function":"g","file":"
// CHECK-SAME: ,"line":17
// CHECK-SAME: ,"dominators":[
// CHECK-NOT: {"text":"b < 5"
// CHECK-SAME: {"text":"a > 0","value":false,"file":"{{.*}}","line":8
// CHECK-SAME: {"text":"b > 10","value":true,"file":"{{.*}}","line":16
