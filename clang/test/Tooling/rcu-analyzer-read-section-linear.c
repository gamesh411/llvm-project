// RUN: clang-rcu-analyzer %s -- 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

int f() {
  rcu_read_lock();
  int x = 0;
  x += 1;
  rcu_read_unlock();
  return x;
}

// CHECK: {"type":"read_section","kind":"linear","function":"f"


