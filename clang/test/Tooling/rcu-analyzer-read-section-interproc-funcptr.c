// RUN: clang-rcu-analyzer --mode=sections %s -- -x c 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

typedef void (*fn_t)(void);

static void unlocker(void) { rcu_read_unlock(); }

static void call_through(fn_t f) { f(); }

int f(void) {
  rcu_read_lock();
  fn_t p = unlocker;
  call_through(p);
  return 0;
}

// The analyzer does not resolve function pointers (no direct callee),
// so it should NOT emit an interprocedural section for f.
// CHECK-NOT: "type":"read_section"





