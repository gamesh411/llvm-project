// RUN: clang-rcu-analyzer --mode=sections %s -- -x c 2>&1 | FileCheck %s

void rcu_read_lock(void);
void rcu_read_unlock(void);

static void b(void) {
  rcu_read_unlock(); // line 6
}

static void a(void) {
  b(); // line 10
}

int f(void) {
  rcu_read_lock();  // line 14
  a();              // line 15
  return 0;
}

// CHECK: {"type":"read_section","kind":"interprocedural","confidence":"definite","function":"f"
// CHECK: "begin_line":15
// CHECK: "end_line":16
// CHECK: "closed_by":"b"
// CHECK-SAME: "line":7
// CHECK-DAG: "function":"f","file":"{{.*}}","line":16,"col":{{[0-9]+}}
// CHECK-DAG: "function":"a","file":"{{.*}}","line":11,"col":{{[0-9]+}}
// CHECK-DAG: "function":"b","file":"{{.*}}","line":7,"col":{{[0-9]+}}


