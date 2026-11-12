# 08: "This path requires" list

**What to build:** A section of the panel lists everything the Bug Path demands, grouped by where each requirement comes from, so a report reader can ask which one is unrealistic and go to the code that assumed it.

**Blocked by:** 02, 04

**Status:** ready-for-agent

- [ ] The section does not depend on the selected Path Step and reads the accumulated path condition of the last Path Step.
- [ ] Rows are grouped from the symbol table: entry inputs (region values rooted in a parameter of the outermost frame, a global or the outermost `this`), call results, replaced values (invalidation, widening and symbols derived from them), and other.
- [ ] Entry inputs come first.
- [ ] Each row shows the label or name, the range, the Path Step whose node last changed it as a link, and that step's function.
- [ ] A trace without the symbol table shows the list ungrouped.
- [ ] A jest test covers the grouping and the "last changed at" step.
- [ ] Verified in a browser at 1400 and 900 pixels on the tmux demo report and on an LLVM report from the triage study decided by entry inputs (cases 6, 27 or 29).
