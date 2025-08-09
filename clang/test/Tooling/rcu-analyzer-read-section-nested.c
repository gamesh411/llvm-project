// RUN: clang-rcu-analyzer --mode=sections %s -- -x c++ -std=c++17 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

int f_nested(int a, int b, int c) {
  rcu_read_lock();
  if (a > 0) {
    while (b < 5) {
      if (c == 1) {
        ++c;
      } else if (c == 2) {
        --c;
      }
      ++b;
    }
  } else {
    b = 6;
  }
  rcu_read_unlock();
  return a + b + c;
}

// CHECK: {"type":"read_section","kind":"branched","function":"f_nested","begin_file":"{{.*}}","begin_line":7
// CHECK-SAME: ,"begin_col":3
// CHECK-SAME: ,"end_file":"{{.*}}","end_line":20
// CHECK-SAME: ,"end_col":3
// CHECK-SAME: ,"conditions":[
// CHECK-SAME: {"text":"a > 0","file":"{{.*}}","line":8
// CHECK-SAME: {"text":"b < 5","file":"{{.*}}","line":9
// CHECK-SAME: {"text":"c == 1","file":"{{.*}}","line":10
// CHECK-SAME: {"text":"c == 2","file":"{{.*}}","line":12
// CHECK-SAME: ]


