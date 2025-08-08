// RUN: clang-rcu-analyzer %s -- 2>&1 | FileCheck %s

struct rcu_head { void *dummy; };
void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head));

void cb(struct rcu_head *head) {}

void g(struct rcu_head *h) { call_rcu(h, cb); }

// CHECK: {"type":"call","name":"call_rcu","function":"g"


