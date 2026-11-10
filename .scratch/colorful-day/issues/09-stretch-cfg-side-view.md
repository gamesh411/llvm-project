# 09: Stretch: CFG side view

**What to build:** When a clicked line needs more selection than the picker offers, a report reader can open a side view of the function's control flow graph, see the relevant Path Steps highlighted, and choose the location there.
Do this only after the demo in ticket 08 works.

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] With the analyzer option on, reports carry the control flow graph of each function on the Bug Path.
- [ ] A side view renders that graph legibly, with statements readable in each block.
- [ ] Blocks and elements on the Bug Path are highlighted.
- [ ] Choosing an element selects the matching Path Step, and the Constraint Snapshot panel updates.
- [ ] Reports with no graph data don't offer the view.
- [ ] The view is checked in a real browser.
