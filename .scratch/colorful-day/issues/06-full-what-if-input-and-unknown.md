# 06: Full What-If input and Unknown handling

**What to build:** A report reader can express a complete hypothesis with terms joined by `&&`, `null` values and constraints on several Path Steps, helped by name suggestions.
Input that can't be evaluated gets a specific explanation instead of a wrong answer.

**Blocked by:** 05

**Status:** ready-for-agent

- [ ] The grammar accepts `variable op value` terms joined by `&&`, with `==`, `!=`, `<`, `<=`, `>`, `>=`, and integer literals or `null` as values.
- [ ] Syntax errors appear beside the input, and the reader's text is kept.
- [ ] What-If Constraints on several Path Steps all apply together in one check.
- [ ] The input suggests variable names from the selected step's Constraint Snapshot.
- [ ] A term on a concretely known value is decided by comparing against that value, so `p == 0` is Infeasible when `p` holds `&x`.
- [ ] A variable with no tracked value at the step gives Unknown and names that variable.
- [ ] A solver timeout gives Unknown and says so.
- [ ] A CodeChecker functional test covers each verdict and error path through the API.
- [ ] Multi-step input and error messages are checked in a real browser.
