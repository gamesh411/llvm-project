// RUN: clang-rcu-analyzer --mode=points %s -- -x c 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

static void calleeA(void) {
  rcu_read_lock();
  rcu_read_unlock();
}

static void calleeB(void) {
  rcu_read_lock();
  rcu_read_unlock();
}

int f(int x, int y, int z) {
  if (x > 0) {
    calleeA();
  } else {
    calleeA();
  }

  if (y == 1) {
    calleeA();
  } else {
    // no call
  }

  if (z != 0) {
    calleeB();
  } else {
    calleeB();
  }

  return x + y + z;
}

// For calleeA events: dominators include x > 0 (true and false), and y == 1 (true)
// CHECK: {"type":"call","name":"rcu_read_lock","function":"calleeA"
// CHECK-SAME: ,"dominators":[{"text":"x > 0","value":true
// CHECK: {"type":"call","name":"rcu_read_lock","function":"calleeA"
// CHECK-SAME: ,"dominators":[{"text":"x > 0","value":false
// CHECK: {"type":"call","name":"rcu_read_lock","function":"calleeA"
// CHECK-SAME: ,"dominators":[{"text":"y == 1","value":true

// Also propagate to unlock in calleeA
// CHECK: {"type":"call","name":"rcu_read_unlock","function":"calleeA"
// CHECK-SAME: ,"dominators":[{"text":"x > 0","value":true
// CHECK: {"type":"call","name":"rcu_read_unlock","function":"calleeA"
// CHECK-SAME: ,"dominators":[{"text":"x > 0","value":false
// CHECK: {"type":"call","name":"rcu_read_unlock","function":"calleeA"
// CHECK-SAME: ,"dominators":[{"text":"y == 1","value":true

// For calleeB events: dominators include z != 0 (true and false)
// CHECK: {"type":"call","name":"rcu_read_lock","function":"calleeB"
// CHECK-SAME: ,"dominators":[{"text":"z != 0","value":true
// CHECK: {"type":"call","name":"rcu_read_lock","function":"calleeB"
// CHECK-SAME: ,"dominators":[{"text":"z != 0","value":false
// CHECK: {"type":"call","name":"rcu_read_unlock","function":"calleeB"
// CHECK-SAME: ,"dominators":[{"text":"z != 0","value":true
// CHECK: {"type":"call","name":"rcu_read_unlock","function":"calleeB"
// CHECK-SAME: ,"dominators":[{"text":"z != 0","value":false


