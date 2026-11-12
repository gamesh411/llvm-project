# 09: A concrete example

**What to build:** A report reader asks for an example and sees, next to every row of "This path requires", one value that follows the Bug Path, including what each opaque call returned.
This ticket closes slice 3 of `../spec.md`.

**Blocked by:** 08

**Status:** ready-for-agent

- [ ] A What-If check whose verdict is Feasible returns one model of the path as symbol and value pairs, only when the request asks for it.
- [ ] A check with no What-If Constraints gives the example for the Bug Path as recorded, and with constraints the example satisfies them.
- [ ] The example uses the existing per-call solver time limit. A timeout gives no example with a reason and does not change the verdict.
- [ ] The request and result gain optional fields and the API minor version is raised once.
- [ ] The example appears as a column of the requires list, labelled as one example of many, and is dropped when the What-If list changes.
- [ ] Pointer values read null or non-null.
- [ ] A report without solver input offers no example and says why.
- [ ] Nothing about an example is stored.
- [ ] Functional tests cover an example when asked, none when not asked, an example under a What-If Constraint, and the timeout through the patched-solver test.
- [ ] Slice acceptance in a browser on the two demos and three LLVM reports from the triage study, with sizes and analysis time reported.
- [ ] The CodeChecker documentation page describes the requires list and the example, including that an example is a model of what the analyzer recorded and not proof of a real execution.
