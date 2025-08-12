// RUN: clang-rcu-analyzer --mode=points --root-function=f %s -- -x c 2>&1 | FileCheck %s --check-prefix=ROOT
// RUN: clang-rcu-analyzer --mode=points %s -- -x c 2>&1 | FileCheck %s --check-prefix=ALL

void rcu_read_lock(void);
void rcu_read_unlock(void);

static void A(void) {
  rcu_read_lock();
  rcu_read_unlock();
}

static void B(void) {
  rcu_read_lock();
  rcu_read_unlock();
}

int f(int c1, int c2) {
  if (c1 > 0) {
    A();
  } else {
    A();
  }
  if (c2 == 7) {
    B();
  }
  return c1 + c2;
}

// When restricted to root f, A and B are reachable; both conditions appear in possibly_dominates for A/B
// ROOT: "name":"rcu_read_lock","function":"A"
// ROOT: "possibly_dominates"
// ROOT: {"text":"c1 > 0","value":true
// ROOT: "possibly_dominates"
// ROOT: {"text":"c1 > 0","value":false
// ROOT: "name":"rcu_read_lock","function":"B"
// ROOT: "possibly_dominates"
// ROOT: {"text":"c2 == 7","value":true

// Without restriction, both still appear (same TU), but this test mainly ensures flag doesn't drop them; contrast achieved by a second file normally.
// ALL: "name":"rcu_read_lock","function":"A"
// ALL: "possibly_dominates"
// ALL: "name":"rcu_read_lock","function":"B"
// ALL: "possibly_dominates"


