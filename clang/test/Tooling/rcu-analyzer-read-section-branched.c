// RUN: clang-rcu-analyzer --mode=sections %s -- -x c++ -std=c++17 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

int f(int c) {
  rcu_read_lock();
  if (c > 0)
    ++c;
  while (c < 3)
    ++c;
  rcu_read_unlock();
  return c;
}

// CHECK: {"type":"read_section","kind":"branched","function":"f","begin_file":"
// CHECK-SAME: ,"begin_line":7
// CHECK-SAME: ,"end_line":12
// CHECK-SAME: ,"conditions":[
// CHECK-SAME: {"text":"c > 0"
// CHECK-SAME: {"text":"c < 3"
// CHECK-SAME: ]


