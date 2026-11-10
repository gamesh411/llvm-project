# 10: Stretch: exploded graph view

**What to build:** When the control flow graph can't resolve a location, for example one statement reached in several calling contexts, a report reader can open a readable view of the part of the exploded graph along the Bug Path and choose the exact analyzer state.
Do this only if time remains after ticket 09.

**Blocked by:** 09

**Status:** ready-for-agent

- [ ] The view is limited to the analyzer states relevant to the Bug Path, so it stays readable on a real report.
- [ ] Each state identifies its calling context and source location.
- [ ] Choosing a state selects the matching Path Step and updates the Constraint Snapshot panel.
- [ ] The added report size is measured on the real report from ticket 08.
- [ ] The view is checked in a real browser.
