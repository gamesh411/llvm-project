## Are dominance and post-dominance equivalent between rcu_lock and rcu_unlock?

We analyze the claim:

Let \(L\) be an occurrence of `rcu_read_lock` and \(U\) be a corresponding `rcu_read_unlock` in the same function CFG. Is it true that
\[
U \text{ post-dominates } L \quad \Longleftrightarrow \quad L \text{ dominates } U\ ?
\]

### Definitions

- A node (basic block) \(X\) dominates a node \(Y\) if every path from the function entry to \(Y\) goes through \(X\).
- A node \(X\) post-dominates a node \(Y\) if every path from \(Y\) to the function exit goes through \(X\).

### Disproof: neither direction holds in general

#### 1) Post-dominance does not imply dominance

Example in C (structured):

```c
void f(int a) {
  if (a) {
    rcu_read_lock();   // L
  } else {
    // other work
  }
  rcu_read_unlock();   // U (after join)
}
```

- From \(L\) to exit, every path must pass the join and then execute \(U\). Hence, \(U\) post-dominates \(L\).
- However, there exists a path from entry to \(U\) through the `else` branch that never visits \(L\). Therefore, \(L\) does not dominate \(U\).

Thus, \(U\) post-dominates \(L\) does not imply \(L\) dominates \(U\).

#### 2) Dominance does not imply post-dominance

Example in C (structured):

```c
void g(int c) {
  rcu_read_lock();      // L (unconditional before the branch)
  if (c) {
    rcu_read_unlock();  // U (only in then-branch)
  }
}
```

- Every path from entry to \(U\) goes through \(L\) (since \(L\) precedes the `if`), so \(L\) dominates \(U\).
- But there exists a path from \(L\) to exit that skips \(U\) (when `c` is false). Hence, \(U\) does not post-dominates \(L\).

Thus, \(L\) dominates \(U\) does not imply \(U\) post-dominates \(L\).

### Conclusion

The equivalence is false. Dominance and post-dominance are independent properties. For a lock/unlock pair to be “well-formed” in the graph-theoretic sense that matches intuitive read-side critical sections, both of the following must hold simultaneously:

1. \(L\) dominates \(U\) (no path can reach the unlock without first taking the lock), and
2. \(U\) post-dominates \(L\) (no path can leave the locked region without passing the unlock).

When both hold, the subgraph between \(L\) and \(U\) forms a single-entry/single-exit region with entry at \(L\) and exit at \(U\). But neither condition implies the other in general.


