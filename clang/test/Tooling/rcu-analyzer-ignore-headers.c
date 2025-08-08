// RUN: clang-rcu-analyzer %s -- -I%S/Inputs 2>&1 | FileCheck %s --allow-empty

#include "has-rcu-calls.h"

void rcu_read_lock(void);
void rcu_read_unlock(void);

int main() { return 0; }

// CHECK-NOT: "name":"rcu_read_lock"
// CHECK-NOT: "name":"rcu_read_unlock"


