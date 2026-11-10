# 03: Complete the Constraint Snapshot

**What to build:** The side panel shows a report reader everything the analyzer knew at a Path Step: variable names mapped to symbols or concrete values, raw symbols that no variable names, what is known at this step, and the accumulated path condition so far.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] A Constraint Snapshot maps visible variables to symbols or concrete values.
- [ ] The panel shows ranges against variable names where a mapping exists.
- [ ] Symbols with no variable name remain visible in the panel.
- [ ] The panel presents "known here" and "accumulated" separately.
- [ ] The accumulated path condition retains constraints on symbols the analyzer has dropped as dead.
- [ ] A Clang lit test proves that a constraint on a dead symbol still appears in the accumulated path condition.
- [ ] The CodeChecker functional test covers the extended data, and the panel is checked in a real browser.
