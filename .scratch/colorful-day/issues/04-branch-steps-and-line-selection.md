# 04: Branch steps and line selection

**What to build:** A report reader can inspect the Constraint Snapshot at control-flow Path Steps and can select a step by clicking its source line.
When a Target Location matches several Path Steps, such as loop iterations, a small picker lets the reader choose one.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Control-flow Path Steps carry a Constraint Snapshot in the plist.
- [ ] When edge optimization merges control-flow pieces, the merged piece keeps the snapshot of its later analyzer node.
- [ ] Clicking a source line on the Bug Path selects its Path Step and updates the side panel.
- [ ] A Target Location matching several Path Steps opens a picker that identifies each one.
- [ ] Clicking a line that is not on the Bug Path leaves the current selection unchanged and tells the reader why.
- [ ] A Clang lit test covers a branch and a loop, and the selection behavior is checked in a real browser.
