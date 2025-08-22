// RUN: clang-rcu-analyzer --mode=sections %s -- -x c++ 2>&1 | FileCheck %s

void rcu_read_lock();
void rcu_read_unlock();

struct Base { virtual void g() {} };
struct Derived : Base { void g() override { rcu_read_unlock(); } };

void call_poly(Base *b) { b->g(); }

int f() {
  rcu_read_lock();
  Derived d;
  call_poly(&d);
  return 0;
}

// The analyzer does not resolve virtual dispatch (requires devirtualization),
// so it should NOT emit an interprocedural section for f.
// CHECK-NOT: "type":"read_section"





