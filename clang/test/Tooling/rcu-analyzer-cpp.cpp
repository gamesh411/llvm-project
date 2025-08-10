// RUN: clang-rcu-analyzer --mode=points %s -- -std=c++17 2>&1 | FileCheck %s

extern "C" void rcu_read_lock(void);
extern "C" void rcu_read_unlock(void);

namespace ns {
struct S {
  int f() const {
    rcu_read_lock();
    rcu_read_unlock();
    return 0;
  }
};
}

// CHECK: {"type":"call","name":"rcu_read_lock","function":"ns::S::f","file":"
// CHECK-SAME: ,"line":9
// CHECK-SAME: ,"dominators":[]
// CHECK: {"type":"call","name":"rcu_read_unlock","function":"ns::S::f","file":"
// CHECK-SAME: ,"line":10
// CHECK-SAME: ,"dominators":[]


