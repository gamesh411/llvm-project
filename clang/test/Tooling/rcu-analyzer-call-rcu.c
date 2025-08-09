// RUN: clang-rcu-analyzer --mode=points %s -- -x c 2>&1 | FileCheck %s

struct rcu_head { void *dummy; };
void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head));

void cb(struct rcu_head *head) {}

void g(struct rcu_head *h) { call_rcu(h, cb); }

// CHECK: {"type":"call","name":"call_rcu","function":"g","file":"
// CHECK-SAME: ,"line":8
// CHECK-SAME: ,"dominators":[


