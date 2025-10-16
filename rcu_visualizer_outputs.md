## RCU visualizer: valuable outputs and insights

This document outlines high-signal outputs a visualizer can generate to help developers understand and audit RCU usage in a codebase.

### Definite read-side critical sections (SESE regions)

Definition (conservative, sound): A pair (L = `rcu_read_lock`, U = `rcu_read_unlock`) forms a definite read-side critical section iff:
- L dominates U, and
- U post-dominates L.

Verification: These two conditions imply a single-entry/single-exit (SESE) region delimited by L (entry) and U (exit). Every path to U goes through L (dominance), and every path from L to exit goes through U (post-dominance). This is a conservative and correct criterion: it may miss some practical “paired” usages that do not strictly satisfy both properties, but all reported pairs are definite sections.

Recommended output for each SESE section:
- Function qualified name
- Begin/end source locations (L and U)
- Active control conditions in the region (dominating predicates and truth values)
- Structural class: linear | branched | loop-involved
- Metrics: basic-block count, statement count, max nesting depth, number of branch points inside
- Nesting info: parent/child sections (if nested), sibling ordering
- CFG snippet identifier(s) to enable on-demand rendering

### High-value warnings and potential issues

- Unlock reachable without prior lock (L does not dominate U): paths-to-U example (minimal counterexample path)
- Lock from which exit is reachable without unlock (U does not post-dominate L): paths-from-L example to exit avoiding U
- Multiple unlocks for a lock (fan-out): list of U sites reached from the same L
- Multiple locks before a single unlock (fan-in): list of L sites that reach the same U
- Double-lock without intervening unlock on some paths (depth growth): show path evidence
- Unlock with zero depth (potential bug): unlock on paths without prior lock
- Locks/unlocks inside loops: classify placement (both inside loop body, lock outside/unlock inside, lock inside/unlock outside)
- Early returns or no-return calls inside a locked region: list with locations

### Contextual control/CFG insights

- Dominator condition deltas: conditions that dominate L but not U, and those that dominate U but not L
- Control-dependency frontier around U: branch points that influence whether U executes
- Post-dominance frontier of L: branch points that allow exiting without U (if any)
- Path complexity: approximate count of distinct entry→U paths and L→exit paths (bounded/estimated)

### Update- vs read-side interactions (cross-checks)

- Occurrences of `rcu_dereference` inside vs. outside sections; flag dereference outside any active read-side section
- Calls to functions that might sleep/block within sections (configurable list), with locations
- Proximity of `rcu_assign_pointer`, `synchronize_rcu`, `call_rcu` relative to sections (same function, caller/callee), potential misuse patterns

### Aggregated metrics and navigation

- Per-function summary: number of sections, coverage (% of basic blocks inside sections), deepest nesting, warnings count
- Per-file summary and heatmap: lines/blocks under RCU protection
- Codebase-level inventory: top N functions by number/size of sections; hotspots with warnings

### Suggested visualizations

- CFG slice with L and U highlighted; nodes/edges inside the SESE region colored
- Dominator tree and post-dominator tree excerpts, highlighting L, U, and frontier nodes
- Timeline view of RCU calls per function (ordered by source) with visual pairing
- Condition badges attached to sections showing predicates that must hold

### Example JSON records (sketch)

```json
{
  "type": "read_section",
  "kind": "sese",
  "function": "foo::bar",
  "begin": {"file": "...", "line": 12, "col": 5},
  "end":   {"file": "...", "line": 34, "col": 7},
  "conditions": [
    {"text": "a > 0", "value": true,  "file": "...", "line": 10, "col": 9},
    {"text": "b < 5", "value": false, "file": "...", "line": 22, "col": 11}
  ],
  "metrics": {"blocks": 8, "stmts": 42, "branches": 3, "max_nesting": 2},
  "nesting": {"parent_id": null, "child_ids": ["sec_17", "sec_18"]},
  "id": "sec_3"
}
```

```json
{
  "type": "warning",
  "kind": "unlock_without_lock_dominance",
  "function": "foo::baz",
  "unlock": {"file": "...", "line": 55, "col": 3},
  "evidence_path_to_unlock": ["BB4", "BB7", "BB11"],
  "note": "Path reaches unlock without passing any rcu_read_lock"
}
```


