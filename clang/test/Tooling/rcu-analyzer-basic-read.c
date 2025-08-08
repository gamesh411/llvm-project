// RUN: clang-rcu-analyzer %s -- 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

int foo() {
  rcu_read_lock();
  int x = 42;
  rcu_read_unlock();
  return x;
}

// CHECK: {"type":"call","name":"rcu_read_lock","function":"foo"
// CHECK: {"type":"call","name":"rcu_read_unlock","function":"foo"


