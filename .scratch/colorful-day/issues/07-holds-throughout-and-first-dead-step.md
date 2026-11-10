# 07: "Holds throughout" and first dead step

**What to build:** A report reader can state that a constraint holds across the whole Bug Path, which tests claims like "this global is never null" even after opaque calls replace its value.
An Infeasible verdict names the earliest Path Step where the path dies.

**Blocked by:** 05

**Status:** ready-for-agent

- [ ] A "holds throughout" toggle applies a term to every value the variable takes across the Bug Path.
- [ ] A global reassigned by an opaque call is constrained both before and after that call when the toggle is on, and only at the anchored value when it is off.
- [ ] An Infeasible verdict names the earliest Path Step whose accumulated path condition, combined with all What-If Constraints, is unsatisfiable.
- [ ] That step can come before the step the constraint is anchored to, and the UI displays this correctly.
- [ ] The named step is selectable from the verdict.
- [ ] A CodeChecker functional test covers both toggle states and the first dead step through the API.
- [ ] The behavior is checked in a real browser.
