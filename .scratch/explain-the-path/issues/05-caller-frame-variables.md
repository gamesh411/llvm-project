# 05: Caller-frame variables

**What to build:** At every Path Step the panel shows the variables of the calling functions as well as the current one, grouped by function, so it is no longer empty inside an inlined callee.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] Clang writes the variables of every frame above the node's own in a new snapshot list, with the frame as part of each entry, encoded as deltas like the other lists.
- [ ] The existing `variables` list keeps its shape and meaning, and the trace stays at version 2.
- [ ] With emission off the plist output is byte-identical to before. Symbol renumbering with emission on is accepted and noted in Comments.
- [ ] Lit covers a Path Step inside an inlined callee two calls deep, with a variable of the same name in two frames.
- [ ] Both readers expose the caller variables through their reader class, with tests.
- [ ] The Variables section is one group per stack frame, each headed by its function and call site, the current frame first and expanded, callers collapsed when there are more than a few.
- [ ] Verified in a browser on the several-contexts demo and on an LLVM report with no variable at its last Path Step today.
- [ ] Plist size on the LLVM run is reported, including the trace with the most stack frames.
