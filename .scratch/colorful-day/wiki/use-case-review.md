# Use case review

Related: [execution plan](execution-plan.md), [data contract](data-contract.md), [web UI decisions](web-ui-decisions.md).
Sources: `../research/triage-study.md`, `../research/health-and-inventory.md`.

## 2026-11-12: the question

On 2026-11-12 the user asked whether What-If constraints on one Bug Path are the best use of the constraint data for people who evaluate bug reports, and what else would serve them.
The lead had a worker measure all 1225 unique traced reports of the LLVM run and triage 30 of them by hand, at `llvm-project@6dc2604108f7` and `codechecker@978ea7699`.
The study is `../research/triage-study.md`, and its limits section applies to everything below: one triager, one C++ project, assertions compiled out.

## 2026-11-12: what the study found

- What-If could express the deciding question in 3 of 30 cases and told the triager something new in 1.
  In 9 more it only negated what the bug event already says, and in 18 nothing could be typed.
- The limit is naming, not solving.
  The panel names 9% of the entries on the final path condition, and What-If can reach 11%.
  75% of entries are raw dumps of conjured, derived, extent or compound symbols.
- 47% of the symbols on path conditions are conjured, and the trace gives only a statement ID for them, with no statement text, callee or reason.
- 76% of bugs end inside an inlined callee and 77% of constraints are added in caller frames, whose variables the panel does not show at that step.
  32% of reports have no variable at all at their last step.
- 28% of path condition changes happen on a control edge with no event, so the Bug Path does not show them.
- tmux, the one C project, differs sharply: 29 of 30 reports have a What-If variable on the path condition at the last step.
- The top triager questions were: where did this value come from (10 cases), does the analyzer know these two facts are correlated (8), can a real caller produce this (7), is there an assert it did not see (6), which assumption does the bug hinge on (5).

## 2026-11-12: the lead's recommendation

On 2026-11-12 the lead recommended to the user that the next work explain the path before it extends What-If, in this order:

1. Symbol origin, Clang side and UI side: for each conjured symbol the statement text, location, callee and reason (return value, invalidation by a call, widening), shown as a label on the symbol.
   It serves the first, second and seventh questions of the study, 21 case mentions.
2. Names: field and element symbols named by access path such as `Builder.InsertPt.Block`, and the variables of caller frames shown at every step.
   It serves the fifth question and raises What-If's reach, which is why it comes before any What-If grammar work.
3. A "this path requires" list: path condition entries grouped by origin (entry inputs, opaque call results, replaced values), steps where the condition changed without an event marked, and a concrete witness from a Z3 model.
   It serves the third question.
4. Readable ranges such as "not 0" for a range that excludes one value. 75% of final ranges are zero or everything but zero.
5. A second LLVM run with assertions on, so the false positive mix is the one a real user sees.
6. What-If grammar (comparing two variables, access paths) only after items 1 and 2.
   Checker state, dynamic type and store contents (4 cases) are a larger, later piece.

Rejected as the next step: more What-If features first, because the study shows the input cannot name what triagers need to talk about.
Rejected: dropping What-If, because on C code its reach is high and items 1 and 2 extend it on C++.

The user's decision on this recommendation is not recorded here yet.
That line is superseded by the 2026-11-12 spec entry below.

## 2026-11-12: spec written

On 2026-11-12 the user approved the recommendation's direction by asking for a spec of items 1 to 3 and for the assertions-on rerun (item 5) to start alongside it.
The spec is `../../explain-the-path/spec.md`.
Its main decisions, made by the lead: the trace stays at version 2 with additive keys (a per-report symbol table and a separate list for caller-frame variables), because a version bump would disable every stored trace; Clang writes the reason "other" when it cannot classify a conjured symbol; What-If accepts access paths and caller variables matched as text against display names; the example is an optional part of a Feasible What-If result.
Readable ranges and the tooltip that stays open (item 4) are kept out of the spec as a direct ticket.

## 2026-11-12: remaining work done the same day

The health check found both branches clean apart from known baselines, as recorded in `../research/health-and-inventory.md`.
User docs were written: `clang/docs/analyzer/developer-docs/ConstraintSnapshots.md` and `docs/web/constraints.md` in codechecker.

On 2026-11-12 the lead accepted a mechanical pass, `codechecker@c902175b1..e23482c40` and `llvm-project@51cfbad5b480`.
The dead `:deep` rules of `Report.vue` apply, the CFG view shows file names for absolute paths, the What-If Check button wraps below a narrow input, and symbol dumps no longer break after a "(" that follows an operator.
`demo/README.md` no longer hardcodes report IDs, and `dev-loop.sh lit` builds the tools the Analysis tests need.
The worker observed the `:deep` fix only as the rule being present and matching, not by hovering a line, and the "(" fix only in the DOM.
Left open as of `codechecker@e23482c40`: at 900px the two checkboxes still wrap below the toolbar buttons, because the toolbar is wider than the pane, and the "Show constraints" tooltip can stay open after a click.

The CodeChecker analyzer unit suite fails the same 13 tests at the merge base `codechecker@bae448521` and at `codechecker@e23482c40`, so the branch causes none of them.
The worker traced 11 to macOS `/tmp` being a symlink to `/private/tmp` and one to needing the packaged clang, and left `test_analyze_correct_analyzer_not_enabled` unexplained.
`dev-loop.sh package` wipes `/Users/efulop/codechecker/build` before it needs Docker, so running it with Docker down leaves no package until Docker is started and it is rerun.

## 2026-11-12: tickets published

On 2026-11-12 the user approved the breakdown of the spec into ten tickets, `../../explain-the-path/issues/01` to `10`, and asked for ticket 10 (readable ranges and the tooltip that stays open) to be done first.
Tickets 01 to 03 are slice 1, 04 to 06 slice 2, and 07 to 09 slice 3; ticket 10 is outside the spec.
On 2026-11-12 the lead decided to run the tickets one at a time, as in the first run, because both repositories have one `colorful-day` branch and the tickets edit the same emission and panel code.
