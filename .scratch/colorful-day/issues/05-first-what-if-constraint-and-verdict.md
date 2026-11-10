# 05: First What-If Constraint and Path Verdict

**What to build:** A report reader types one `variable op value` What-If Constraint at the selected Path Step and presses Check.
The CodeChecker server solves it with Z3 and returns a Feasible or Infeasible Path Verdict along with the Baseline Verdict.
On the two-path example, `b == 0` returns Infeasible and the result is worded as being about this path.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] With a Z3-enabled Clang, the plist carries SMT-LIB built with the same symbol encoding as the Z3 crosscheck.
- [ ] Without Z3, Clang still emits readable ranges, and a check reports Unknown instead of failing.
- [ ] The Python Z3 package is a CodeChecker server dependency.
- [ ] A new Thrift method takes a report ID and What-If Constraints and returns a Path Verdict and a Baseline Verdict, and requires only product view permission.
- [ ] Solving applies a short fixed timeout.
- [ ] A variable resolves to the symbol it holds at the anchored Path Step.
- [ ] Solving starts only when the reader presses Check.
- [ ] A Baseline Verdict that is not Feasible is shown separately from the result of the reader's constraint.
- [ ] What-If Constraints are not written to the database.
- [ ] Every verdict is worded as being about this path, not this bug.
- [ ] A CodeChecker functional test covers Feasible, Infeasible and a non-Feasible Baseline Verdict through the API.
- [ ] The two-path `b == 0` case is checked in a real browser.
