# 07: What changed here

**What to build:** A report reader sees at a glance what the selected Path Step did to the analyzer's knowledge, and notices Path Steps where the analyzer made an assumption that the Bug Path has no event for.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Entries of the Constraint Snapshot and of the accumulated path condition that were added or narrowed at the selected Path Step are highlighted, using the deltas the trace already has.
- [ ] A Path Step that changes the path condition and is a control step with no event on its node gets a marker in the report tree and at its place in the source.
- [ ] The marker has a tooltip that says the analyzer assumed something here that the Bug Path does not describe.
- [ ] Reader jest tests cover which entries changed at a step and which steps are silent changes.
- [ ] No trace or API change.
- [ ] Verified in a browser on the two-path demo and on an LLVM report from the triage study whose deciding constraint had no event (cases 18 or 25).
