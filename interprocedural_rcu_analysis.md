## Interprocedural RCU analysis: dominator conditions and read-side critical sections

This document sketches approaches to incorporate multiple functions (calls within function bodies) when computing:
- a) Dominator conditions for a single point (RCU-related call), and
- b) Read-side critical sections (lock/unlock pairs), potentially spanning calls.

### Goals and constraints

- Work over an interprocedural control-flow representation (ICFG) or equivalent summaries.
- Stay conservative in presence of unknown/indirect calls; avoid false safety.
- Make results explorable by the visualizer and scalable to large codebases.

### Core building blocks

- Call graph (CG) with edges from caller to callee; identify SCCs for recursion.
- Interprocedural CFG (ICFG) view: expand a call to a callee entry, and returns back to the call-site continuation.
- Function summaries capturing RCU-relevant behavior and control constraints.

### Function summaries (per callee)

For each function F, compute and cache a summary:
- Conditions
  - Entry-dominating predicate templates (parameterized by F’s formals/global state symbols) that dominate specific RCU points inside F.
  - Per-RCU-point dominating conditions (as AST-based expressions with source locations), factored by parameters.
- RCU effects
  - Lock/unlock actions in transfer form: delta to lockDepth; minimal and maximal net effect along any path from entry to exit.
  - Whether F may call unlock without a preceding lock (w.r.t. entry state), or may return with positive lockDepth.
  - Whether F always (on all paths) performs an unlock when entered with depth > 0 (useful for post-dominance reasoning).
- Control frontiers
  - For each RCU point P in F, the set of branching sites inside F that (intra-F) determine reachability of P, with truth value classification.
- Exits
  - Set of exit kinds: normal return, no-return call, longjmp-like if modeled (configurable); used to guard post-dominance.

Representation tips:
- Store conditions as canonicalized AST snippets with stable IDs and presumed locations.
- Allow symbols for parameters and a small set of globals (optional alias analysis for pointers to shared state).

### Computing dominator conditions for a point across calls (a)

Target: an RCU-related point P that may be inside a callee reachable from caller C.

Options:
- Inline expansion (bounded): Inline small/whitelisted callees into the caller CFG; compute dominators on the expanded CFG. Pros: simpler; Cons: code blow-up, limited depth.
- Summary lifting (recommended):
  1. Compute \(\mathsf{DomConds}_{intra}(P)\) inside the callee F using CFG dominator tree.
  2. Compute \(\mathsf{DomConds}_{call}(\text{call to }F)\) at the caller site C (conditions dominating the call site).
  3. Interprocedural dominators for P at this call-site context are \(\mathsf{DomConds}_{ICFG}(P) = \mathsf{DomConds}_{call} \cup \mathsf{DomConds}_{intra}(P)\), after substituting callee-parameter symbols with caller arguments where feasible.
  4. If multiple call-sites reach P (via different call paths), merge per-context results (e.g., intersect for must-dominators, union with provenance for may-dominators). Expose both “must” and “may” views.

Context sensitivity:
- Use k-limited call strings or value contexts for predicates that depend on arguments; bound k for scalability.
- For recursion/SCCs, solve summaries to a fixpoint (monotone framework over a finite-height lattice of predicates/effects).

Unknown and indirect calls:
- If callee body unavailable or function pointer unresolved: conservatively assume it does not add dominators for P, and may affect reachability (mark results as “may” only). Optionally allow user-provided stubs/summaries.

### Interprocedural read-side critical sections (b)

We want to detect pairs (L, U) that may span calls, and classify definite SESE sections when possible.

ICFG-based definition:
- Treat the program as an interprocedural graph with call/return edges.
- A pair (L, U) is a definite section if L dominates U in the ICFG and U post-dominates L in the ICFG.

Summary-based algorithm (scalable):
1. For each function F, compute summary over lockDepth:
   - Path effects: min/max lockDepth delta from entry to exit.
   - Obligations: does F guarantee an unlock when entered with depth > 0? does it possibly unlock at depth 0?
   - Intra-F pairs: SESE (L, U) inside F.
2. For each call-site, propagate caller state (current lockDepth and dominator condition set) into callee summary, transform, and combine at return.
3. When a lock in caller is followed by calls, use callee summaries to determine whether an unlock in the callee (or in later code) post-dominates that lock on all interprocedural paths.
4. Report interprocedural SESE if both hold in the ICFG:
   - Call-site-dominance: No path reaches U (possibly in callee) without passing through L (possibly in caller or another callee). Use summaries + call graph reachability.
   - Post-dominance: From L, all paths to exit must encounter U (accounting for callees’ exits). Disallow unknown no-return or early-return behaviors unless summarized as safe.

Heuristics for practicality:
- Limit analysis depth; inline/summarize small wrappers (typical for RCU APIs).
- Treat known wrappers (e.g., convenience functions that only lock/unlock) as transparent via handcrafted summaries.
- Flag results with confidence levels (definite when both dominance/post-dominance proven; probable when dominance holds and post-dominance holds modulo unknown calls).

### Handling complex features

- Function pointers/virtual dispatch: resolve via points-to sets where available; otherwise conservatively join summaries.
- Recursion: analyze SCCs to a fixpoint; cap iterations.
- Exceptions (C++): model exceptional exits as additional edges; count as potential escape unless summary proves no-throw.
- Longjmp/setjmp or signals: configurable; default conservative.

### Outputs for the visualizer

- Interprocedural dominator conditions for a selected point P: list of predicates with provenance:
  - Source location and text
  - Origin: caller site vs. inside callee F (with function name)
  - Must vs. may classification
- Interprocedural sections:
  - (L, U) pairs with locations and functions; SESE status (definite/probable)
  - Call-chain(s) witnessing the pair; minimal counterexample paths if not SESE
  - Metrics across calls: number of functions spanned, depth of call chain, blocks/statements inside region (estimated)
- Warnings across calls:
  - Unlock reachable without prior lock across call boundary
  - Lock that may return (from some callee) without unlock
  - Mismatched wrapping helpers (lock in wrapper A, unlock in wrapper B)

### Implementation roadmap (incremental)

1. Summaries v1: intra-procedural dominator conditions per RCU point; lock/unlock effects; exits classification.
2. Call-site lifting: compute interprocedural dominators for callee points using caller-site dominators + summaries.
3. Interprocedural sections v1: same-function caller with single-level callee expansion (no recursion, bounded depth).
4. Fixpoint over call graph SCCs; confidence levels; unknown-call handling.
5. Visualizer integration: provenance, filters (definite/probable), and call-chain rendering.


