// RUN: clang-rcu-analyzer --mode=points --root-function=f %s -- -x c 2>&1 | FileCheck %s --check-prefix=ROOTF
// RUN: clang-rcu-analyzer --mode=points --root-function=g %s -- -x c 2>&1 | FileCheck %s --check-prefix=ROOTG
// RUN: clang-rcu-analyzer --mode=points %s -- -x c 2>&1 | FileCheck %s --check-prefix=ALL

void rcu_read_lock(void);
void rcu_read_unlock(void);

static void C(void) {
  rcu_read_lock();
  rcu_read_unlock();
}

int f(int a) {
  if (a > 0) {
    C();
  }
  return a;
}

int g(int b) {
  if (b == 1) {
    C();
  } else {
    C();
  }
  return b;
}

// With root f: only a > 0 (true) is propagated; it is also definite (single call-site)
// ROOTF: "name":"rcu_read_lock","function":"C"
// ROOTF: "possibly_dominates"
// ROOTF: "definitely_dominates"
// ROOTF-NOT: "b == 1"

// With root g: both b == 1 truth values are propagated; none are definite (two call-sites)
// ROOTG: "name":"rcu_read_lock","function":"C"
// ROOTG: "possibly_dominates"
// ROOTG: "possibly_dominates"
// ROOTG: "definitely_dominates"
// ROOTG-NOT: "a > 0"

// Without restriction: union of all caller conditions; still not definite due to multiple call-sites overall
// ALL: "name":"rcu_read_lock","function":"C"
// ALL: "possibly_dominates"
// ALL-DAG: {"text":"a > 0","value":true
// ALL-DAG: {"text":"b == 1","value":true
// ALL-DAG: {"text":"b == 1","value":false
// ALL: "definitely_dominates"


