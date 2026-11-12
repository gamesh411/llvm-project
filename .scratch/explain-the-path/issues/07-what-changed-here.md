# 07: What changed here

**What to build:** A report reader sees at a glance what the selected Path Step did to the analyzer's knowledge, and notices Path Steps where the analyzer made an assumption that the Bug Path has no event for.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] Entries of the Constraint Snapshot and of the accumulated path condition that were added or narrowed at the selected Path Step are highlighted, using the deltas the trace already has.
- [x] A Path Step that changes the path condition and is a control step with no event on its node gets a marker in the report tree and at its place in the source.
- [x] The marker has a tooltip that says the analyzer assumed something here that the Bug Path does not describe.
- [x] Reader jest tests cover which entries changed at a step and which steps are silent changes.
- [x] No trace or API change.
- [x] Verified in a browser on the two-path demo and on an LLVM report from the triage study whose deciding constraint had no event (cases 18 or 25).

## Comments

Built in codechecker as `fc52a8e3f` (web) and `6ed777923` (docs).

What: `ConstraintTrace.changedAt(order)` gives the symbols added or narrowed in the symbol ranges and the path condition, and `silentChanges()` the silent control steps.
Both are cached and built from the raw lists and deltas, so a step click builds nothing new that a snapshot does not.
The panel tags changed rows `new` or `narrowed` with a coloured bar, so colour is not the only signal.
A silent step is marked by a small icon in the report tree, an amber bar and an `assumes` tag in the source, and an `Assumed, no event` tag in the panel, each with the ticket's tooltip.
The tree and the report view now share one parsed trace through `constraintTraceOf` in the details cache.

Decisions:
- The baseline of "changed" is the closest earlier step with a different snapshot, not the previous node, because the printed path is not in node order and an event and its edge share a snapshot.
- A step is silent only when its node is later than every node before it and adds to the path condition, so a jump back in a printed path never counts as a new assumption.
- The Bug Path has no tree item for a control step, so the tree marker sits on the event next to it, with the icon before the text because the tree clips labels at 900px.

Verified on the two-path demo (no silent step, `b` shown as new), VPlanLowering.cpp:198 (report 2273, case 18) and X86ISelLowering / MachineValueType.h:325 (report 3402, case 25), at 1400 and 900px.
Case 25's deciding constraint was seen as a silent step in report 3402 only; report 2295 has none.
Step click on LLVM report 3142 (10 tree clicks, page settled, median of paint after click): 1100 ms before, 1090 ms after; the 1-7 s outliers are source file loads and are the same in both.

Ticket 10 carry-over: the line picker on `several-contexts.c` line 13 reads `a = not 0, p = 0`, and the hover title holds `{ [-2147483648, -1], [1, 2147483647] }`.
Nothing to fix.

Not done: a legend for the tags; the first step highlights nothing, as it has no step before it.
