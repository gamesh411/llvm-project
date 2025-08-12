// RUN: clang-rcu-analyzer --mode=sections %s -- -x c++ -std=c++17 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

void unconditionally_nested() {
  rcu_read_lock();
  rcu_read_lock();
  rcu_read_unlock();
  rcu_read_unlock();
}

// CHECK: {"type":"read_section","kind":"linear","function":"unconditionally_nested","begin_file":"{{.*}}","begin_line":7
// CHECK-SAME: ,"begin_col":3
// CHECK-SAME: ,"end_file":"{{.*}}","end_line":10
// CHECK-SAME: ,"end_col":3

// CHECK: {"type":"read_section","kind":"linear","function":"unconditionally_nested","begin_file":"{{.*}}","begin_line":8
// CHECK-SAME: ,"begin_col":3
// CHECK-SAME: ,"end_file":"{{.*}}","end_line":9
// CHECK-SAME: ,"end_col":3


void conditionally_unlocked_section(int a) {
  rcu_read_lock();
  if (a > 0) {
    rcu_read_unlock();
  }
  rcu_read_unlock();
}

// CHECK: {"type":"read_section","kind":"branched","function":"conditionally_unlocked_section","begin_file":"{{.*}}","begin_line":25
// CHECK-SAME: ,"begin_col":3
// CHECK-SAME: ,"end_file":"{{.*}}","end_line":29
// CHECK-SAME: ,"end_col":3



void conditionally_interrupted_section(int a) {
  rcu_read_lock();
  if (a > 0) {
    rcu_read_unlock();
  }
  if (a > 0) {
    rcu_read_unlock();
  }
  rcu_read_unlock();
}

// CHECK: {"type":"read_section","kind":"branched","function":"conditionally_interrupted_section","begin_file":"{{.*}}","begin_line":40
// CHECK-SAME: ,"begin_col":3
// CHECK-SAME: ,"end_file":"{{.*}}","end_line":47
// CHECK-SAME: ,"end_col":3


void conditionally_interrupted_section_with_different_condition(int a, int b) {
  rcu_read_lock();
  if (a > 0) {
    rcu_read_unlock();
  }
  if (b > 0) {
    rcu_read_unlock();
  }
  rcu_read_unlock();
}

// CHECK: {"type":"read_section","kind":"branched","function":"conditionally_interrupted_section_with_different_condition","begin_file":"{{.*}}","begin_line":57
// CHECK-SAME: ,"begin_col":3
// CHECK-SAME: ,"end_file":"{{.*}}","end_line":64
// CHECK-SAME: ,"end_col":3


