// RUN: clang-rcu-analyzer %s -- 2>&1 | FileCheck %s

void synchronize_rcu(void);
void rcu_assign_pointer(void **p, void *v);

static void *global_ptr;

void bar(void *newp) {
  rcu_assign_pointer(&global_ptr, newp);
  synchronize_rcu();
}

// CHECK: {"type":"call","name":"rcu_assign_pointer","function":"bar"
// CHECK: {"type":"call","name":"synchronize_rcu","function":"bar"


