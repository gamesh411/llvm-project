// RUN: clang-rcu-analyzer %s -- 2>&1 | FileCheck %s

struct foo { int x; };
void *rcu_dereference(void *p);

static void *global_ptr;

int use() {
  struct foo *ptr = (struct foo *)rcu_dereference(global_ptr);
  return ptr ? ptr->x : 0;
}

// CHECK: {"type":"call","name":"rcu_dereference","function":"use"


