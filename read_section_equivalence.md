## Read-side section equivalence: post-dominance vs. dominator conditions

This note formalizes and analyzes the relationship between post-dominance of RCU calls in a control-flow graph (CFG) and the sets of dominating boolean conditions (with truth assignments) that hold at those calls.

We consider two statements in the same function: an earlier RCU call \(L\) (e.g., `rcu_read_lock`) and a later RCU call \(U\) (e.g., `rcu_read_unlock`). Let \(\mathsf{DomConds}(S)\) denote the set of control predicates with fixed truth values that (graph-theoretically) dominate the basic block containing statement \(S\), in the sense that each such predicate's block dominates \(S\) and exactly one of its outgoing edges reaches \(S\). Intuitively, \(\mathsf{DomConds}(S)\) are the branch decisions that must be true/false along all paths from entry to \(S\).

We ask whether the following equivalence is true:

\[ U \text{ post-dominates } L \quad \Longleftrightarrow \quad \mathsf{DomConds}(U) \subseteq \mathsf{DomConds}(L). \]

### Definitions

- A node (basic block) \(X\) post-dominates a node \(Y\) iff every path from \(Y\) to function exit contains \(X\).
- A condition block \(C\) with predicate \(p\) is in \(\mathsf{DomConds}(S)\) with value \(v\in\{\text{true},\text{false}\}\) iff:
  1. \(C\) dominates \(S\) in the standard dominator-tree sense (from entry), and
  2. exactly one successor of \(C\) can reach \(S\); call that successor the \(v\)-successor with respect to \(S\).

### Theorem (necessity)

If \(U\) post-dominates \(L\), then \(\mathsf{DomConds}(U) \subseteq \mathsf{DomConds}(L)\).

#### Proof

Pick any condition block \(C\in\mathsf{DomConds}(U)\) with predicate text \(p\) and fixed value \(v\). By definition of \(\mathsf{DomConds}(U)\):

1. \(C\) dominates \(U\).
2. Exactly one successor of \(C\) reaches \(U\) (the \(v\)-successor).

Assume \(U\) post-dominates \(L\). Consider any path from entry to \(L\), then any continuation from \(L\) to exit. Because \(U\) post-dominates \(L\), every such continuation must pass through \(U\). Since \(C\) dominates \(U\), it follows that every continuation from \(L\) to exit must also pass through \(C\) before reaching \(U\). At \(C\), taking the non-\(v\) successor would lead to a region that cannot reach \(U\) (by item 2), contradicting the assumption that \(U\) post-dominates \(L\). Hence on all \(L\)\(\to\)exit paths, \(C\)'s \(v\)-successor must be taken.

Therefore, \(C\) also lies on all entry\(\to\)\(L\) paths (otherwise there would be an entry\(\to\)\(L\) path avoiding \(C\), and extending it to exit would include a choice at \(C\) that could avoid \(U\), again contradicting post-dominance). Thus \(C\) dominates \(L\), and since the \(v\)-successor is enforced on all paths to \(U\), it is enforced along all paths to \(L\) that continue to exit as well.

Hence \(C\in\mathsf{DomConds}(L)\) with the same value \(v\). As \(C\) was arbitrary, \(\mathsf{DomConds}(U) \subseteq \mathsf{DomConds}(L)\).
\(\square\)

### Counterexample (insufficiency)

The converse implication is not generally true. The subset condition can hold while \(U\) fails to post-dominate \(L\). Consider the following structured C example:

```c
void f(int a, int b) {
  if (a) {
    rcu_read_lock();           // L
    if (b) {
      return;                  // early exit, avoids U
    }
  } else {
    // fall through
  }
  rcu_read_unlock();           // U
}
```

- There exists a path from \(L\) to exit that avoids \(U\) (when \(a\) and \(b\) are both true), so \(U\) does not post-dominate \(L\).
- Dominating conditions:
  - \(\mathsf{DomConds}(L) = \{\, a=\text{true} \,\}\) (the outer `if (a)` dominates \(L\)).
  - \(\mathsf{DomConds}(U) = \emptyset\). The outer `if (a)` does not dominate \(U\) (the \(a=\text{false}\) branch reaches \(U\)), and the inner `if (b)` also does not dominate \(U\) (it is bypassed when \(a=\text{false}\)).

Thus \(\mathsf{DomConds}(U)\subseteq\mathsf{DomConds}(L)\) holds (\(\emptyset\subseteq\{a=\text{true}\}\)), yet \(U\) does not post-dominate \(L\). This contradicts the \(\Leftarrow\) direction, so the “iff” claim is false.

### Correct relationship

- The subset condition is **necessary**: if \(U\) post-dominates \(L\), then \(\mathsf{DomConds}(U) \subseteq \mathsf{DomConds}(L)\).
- The subset condition is **not sufficient** in general.

A precise graph-theoretic characterization of post-dominance that aligns with the above intuition is:

\[ U \text{ post-dominates } L \quad \Longleftrightarrow \quad \text{There is no condition block } C \text{ reachable from } L \text{ such that exactly one successor of } C \text{ reaches } U. \]

Equivalently: after \(L\), every conditional terminator either (a) has both successors eventually reach \(U\), or (b) has neither successor reach \(U\) (which implies \(U\) is unreachable from \(L\) at all). This condition is independent of entry-based dominators and is directly equivalent to the standard definition of post-dominance.

In practice, the subset test on \(\mathsf{DomConds}(\cdot)\) is a sound necessary check: when it fails, \(U\) cannot post-dominate \(L\). Passing the subset test is a useful filter, but additional reachability analysis from \(L\) is required to conclude post-dominance.

### On removing early returns and no-return calls

A natural question is whether the equivalence becomes true if we forbid early `return` statements and calls to no-return functions (so every path conceptually flows forward to the function exit).

The answer is still “not necessarily.” Even without early returns or no-return calls, it is possible to branch after \(L\) and reach the function exit without visiting \(U\). For example:

```c
void f(int a, int c) {
  if (a) {
    rcu_read_lock();    // L
  }
  if (c) {
    rcu_read_unlock();  // U
  }
  // normal fallthrough to function exit (no early return)
}
```

Here, when `a` is true and `c` is false, there exists a path from \(L\) to exit that does not pass through \(U\), so \(U\) does not post-dominate \(L\). The dominator-condition sets are \(\mathsf{DomConds}(L)=\{a=\text{true}\}\) and \(\mathsf{DomConds}(U)=\{c=\text{true}\}\); the subset condition fails (hence no contradiction), and the “iff” claim still does not hold.

More strongly, even aiming for the \(\Leftarrow\) direction (sufficiency), the absence of early returns/no-return calls alone does not guarantee that \(\mathsf{DomConds}(U) \subseteq \mathsf{DomConds}(L)\) implies that \(U\) post-dominates \(L\). To make the implication hold, one needs an additional structural assumption:

Sufficient structural condition (one-way): If every conditional that has a successor which cannot reach \(U\) is itself a dominator of \(U\) (intuitively, all “choices that can exclude \(U\)” occur before \(U\) and dominate it), then
\[
\mathsf{DomConds}(U) \subseteq \mathsf{DomConds}(L)\ \Longrightarrow\ U \text{ post-dominates } L.
\]

Reason: Under this assumption, any attempt to avoid \(U\) after \(L\) must take a non-\(U\) successor at some dominator of \(U\), but those dominators (with their enforced successor choices) appear in \(\mathsf{DomConds}(U)\). The subset condition then forces the same successor choices for \(L\), contradicting the existence of an \(L\to\)exit path that avoids \(U\).

This sufficient condition is typically met in strictly nested, well-structured (reducible) control where \(U\) is placed after all conditionals that determine whether it will execute (i.e., \(U\) is not nested inside a new conditional that does not also dominate \(L\)). Absent such structure, the equivalence remains false in general, even without early returns or no-return calls.


