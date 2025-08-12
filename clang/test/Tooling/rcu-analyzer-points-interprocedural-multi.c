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

// For calleeA: union includes x > 0 (true and false) and y == 1 (true)
// CHECK: "name":"rcu_read_lock","function":"calleeA"
// CHECK: "possibly_dominates"
// CHECK-DAG: {"text":"x > 0","value":true
// CHECK-DAG: {"text":"x > 0","value":false
// CHECK-DAG: {"text":"y == 1","value":true
// CHECK: "definitely_dominates"

// For calleeB: union includes z != 0 (true and false)
// CHECK: "name":"rcu_read_lock","function":"calleeB"
// CHECK: "possibly_dominates"
// CHECK-DAG: {"text":"z != 0","value":true
// CHECK-DAG: {"text":"z != 0","value":false
// CHECK: "definitely_dominates"


