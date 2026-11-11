Status: ready-for-agent

# Colorful Day: show and challenge the constraints behind a Bug Path

## Problem Statement

A CodeChecker user reading a static analyzer report sees what the analyzer did, such as "Assuming 'a' is 0", but not the value ranges it held at each step.
Deciding whether a report is real means rebuilding those constraints by hand.
The user often knows something the analyzer doesn't, such as "this global is never null", and has no way to test whether that knowledge rules the report's path out.
Today the only other option is changing the code or dumping an exploded graph, and an exploded graph is too large to read for this purpose.

## Solution

Clang can optionally record, for every Path Step, what the analyzer knew at that point.
CodeChecker stores that data and shows it in its web UI behind a toggle.
The user clicks a Path Step, reads its Constraint Snapshot, types What-If Constraints such as `a == 0 && n > 3`, and presses Check.
The server answers with a Path Verdict for this Bug Path: Feasible, Infeasible with the first step where the path dies, or Unknown with the reason.

This is a throwaway, demo-driven hackathon prototype spread over two repositories, each with its own `colorful-day` branch.

## User Stories

1. As an analyzer developer, I want constraint emission off by default, so that normal analysis output doesn't change.
2. As an analyzer developer, I want to enable emission with an analyzer config option, so that no new compiler flag is needed.
3. As a CodeChecker user, I want to enable emission through the existing analyzer config passthrough, so that CodeChecker gains no new CLI flag.
4. As a report reader, I want the debug view off by default, so that the report page looks the same until I ask for more.
5. As a report reader, I want a toggle next to "Show arrows", so that I can find the debug view where the other path display options are.
6. As a report reader, I want the toggle disabled with an explanation on reports without constraint data, so that I know why the view is unavailable.
7. As a report reader, I want clicking a Path Step to open a side panel, so that the source view stays uncluttered.
8. As a report reader, I want the panel to list the ranges known at the selected Path Step, so that I can see what the analyzer knew there.
9. As a report reader, I want ranges shown against variable names where a mapping exists, so that I don't have to decode analyzer symbols.
10. As a report reader, I want raw symbols still visible, so that I can see constraints on values no variable currently names.
11. As a report reader, I want to see both what is known at this step and the accumulated path condition, so that constraints on dead values don't disappear from view.
12. As a report reader, I want Constraint Snapshots at branches as well as events, so that I can inspect the point where the path split.
13. As a report reader, I want clicking a source line to select its Path Step, so that I can work from the code I am reading.
14. As a report reader, I want a small picker when a Target Location matches several Path Steps, so that I can choose a specific loop iteration.
15. As a report reader, I want to type What-If Constraints using the form `variable op value`, so that a hypothesis takes seconds to write.
16. As a report reader, I want to join terms with `&&`, so that one hypothesis can cover several variables.
17. As a report reader, I want variable names suggested from the Constraint Snapshot, so that I only type names that exist at that step.
18. As a report reader, I want a What-If Constraint to hold at the selected Path Step by default, so that `x` at step 3 and `x` at step 9 stay separate values.
19. As a report reader, I want a "holds throughout" toggle, so that I can test claims like "this global is never null" across calls that invalidate it.
20. As a report reader, I want to add What-If Constraints on several Path Steps and have them all apply, so that I can test a combined hypothesis.
21. As a report reader, I want a Check button, so that half-typed input is never solved.
22. As a report reader, I want a Feasible verdict when the Bug Path survives my constraints, so that I know my hypothesis doesn't rule it out.
23. As a report reader, I want an Infeasible verdict to name the first Path Step where the path dies, so that I can see where the contradiction appears.
24. As a report reader, I want an Unknown verdict to name the variable or condition responsible, so that I can correct the hypothesis.
25. As a report reader, I want a solver timeout reported as Unknown, so that the page never waits indefinitely.
26. As a report reader, I want a syntax error reported next to my input, so that I can fix it without losing the rest.
27. As a report reader, I want a constraint on a concretely known value checked against that value, so that `p == 0` is Infeasible when `p` holds `&x`.
28. As a report reader, I want every verdict worded as being about this path, so that I don't conclude the bug is gone when another route still reaches it.
29. As a report reader, I want to be told when the Bug Path is already not Feasible with no What-If Constraints, so that my constraint doesn't get blamed for it.
30. As a report reader, I want What-If Constraints to stay temporary, so that exploring a hypothesis leaves nothing behind in the product database.
31. As a CodeChecker administrator, I want no database schema migration, so that the prototype can be stored by an existing server schema.
32. As a CodeChecker administrator, I want solver work limited by a short timeout, so that a hard query can't hold an API worker for long.
33. As a CodeChecker administrator, I want the page's Content Security Policy unchanged, so that the demo doesn't weaken the server's headers.
34. As a demo presenter, I want a hand-written two-path example, so that I can explain "this path" against "this bug" in a minute.
35. As a demo presenter, I want a real report from FFmpeg, tmux or Vim, so that the feature is shown on code people recognize.

## Implementation Decisions

Build order:

1. Clang emits the data, CodeChecker stores it, and the web UI shows the toggle and Constraint Snapshot.
2. What-If Constraints and Path Verdicts.
3. CFG side view, as a stretch goal.
4. Exploded graph view, only if time remains.

Clang changes:

- A new off-by-default analyzer config option controls emission, and the plist output gains a new per-diagnostic key that only appears when the option is on.
- CodeChecker's plist parser reads only the keys it knows, so older viewers ignore the new key.
- Path pieces don't link to analyzer nodes today, so piece construction records the node each piece came from.
- Each event and control-flow piece gets a Constraint Snapshot from that node.
- When edge optimization merges control-flow pieces, the merged piece keeps the snapshot of its later node.
- A Constraint Snapshot holds symbol ranges, a map from visible variables to symbols or concrete values, and the accumulated path condition up to that step.
- The accumulated path condition keeps constraints on symbols the analyzer has since dropped as dead, as the Z3 crosscheck visitor does.
- Solver input is SMT-LIB built with the same symbol encoding as the Z3 crosscheck, alongside human-readable ranges.
- Emitting SMT-LIB needs a Z3-enabled Clang. Without Z3, Clang still emits readable ranges and the report shows Unknown for What-If checks.

CodeChecker changes:

- The report converter's plist parser and report model carry the per-step data.
- Storage adds a new item type to the existing compressed report path data blob, which needs no database migration.
- The report detail query currently treats any unrecognized item type as extended report data, so the new type gets its own branch.
- The Thrift API gains an optional serialized trace field on report details and a new what-if method.
- The method takes a report ID and a list of What-If Constraints, each with a Path Step, an expression and a "holds throughout" flag.
- It returns a Path Verdict, the first dead Path Step when Infeasible, a reason when Unknown, and the Baseline Verdict.
- It needs only product view permission.
- API code is regenerated with the Thrift Docker image CodeChecker pins.

What-If evaluation:

- Evaluation runs on the CodeChecker server through the Python Z3 package, added as a server dependency.
- A short fixed solver timeout applies to each check.
- The grammar is `variable op value` terms joined by `&&`, with operators `==`, `!=`, `<`, `<=`, `>`, `>=`, and integer literals or `null` as values.
- The range-based forward solver only records constraints of about this shape, so a larger grammar buys little.
- A variable at a Path Step resolves to that step's symbol or concrete value, and symbols never change value, so the anchor only decides which value a name refers to.
- "Holds throughout" applies the term to every value the variable takes across the Bug Path's Path Steps.
- A term on a concrete value is decided directly by comparing the two.
- A variable with no tracked value at the step yields Unknown and names that variable.
- The server evaluates the Baseline Verdict first, and reports it separately if it isn't Feasible.
- The first dead Path Step is the earliest step whose accumulated path condition, combined with all What-If Constraints, is unsatisfiable. It can come before the step a constraint is anchored to.

Web UI:

- The toggle sits beside "Show arrows" and defaults to off.
- The side panel shows the Constraint Snapshot, the what-if input and the verdict.
- What-If Constraints exist only in the open report view.

Repository handling:

- Each repository uses a local `colorful-day` branch, with commits at milestone boundaries, terse messages and no co-author line.
- Nothing is pushed until the user asks.
- The LLVM branch holds all docs.

## Testing Decisions

A good test exercises behavior through a public boundary and doesn't depend on internal classes or on how the data gets built.

- Clang seam: lit tests run the analyzer with the option on and check the plist output, including Path Step coverage, variable mapping and accumulated constraints on dead symbols. Existing plist tests in the analyzer test suite and the Z3-gated tests are the prior art.
- CodeChecker seam: functional tests store a fixture plist and call the Thrift API. One test run covers parsing, blob storage, report details and all Path Verdict outcomes. The existing extended report data functional test is the prior art.
- The fixture plist comes from the Clang build, so it is the contract between the two repositories.
- A report with no constraint data is a required case at the CodeChecker seam.
- The web UI has no committed tests. It is verified by driving a real browser against a live server with the two-path example and one real report, and that check includes visual review of the panel.

## Out of Scope

- Bug-level answers, such as whether the bug survives on another route, which require re-running the analyzer.
- Injecting What-If Constraints into forward analysis.
- A standalone reachability query from function entry.
- Starting analysis at an arbitrary program point.
- Seeding analysis from dataflow results, or dataflow from analysis.
- Saving or sharing What-If Constraints.
- Static HTML output from `CodeChecker parse`.
- A new CodeChecker CLI flag.
- A full C expression parser for What-If Constraints.
- Upstream submission and production hardening.
- Z3 running in the browser, which was rejected over a 40 MB package, a CSP exception and doubts about its nested workers.

## Further Notes

Open concern about solver mismatch, raised by the user and not yet evaluated.
The analyzer explores forward with its range-based constraint manager and uses Z3 only to refute finished Bug Paths.
What-If evaluation with Z3 therefore matches the refutation stage and doesn't model the forward solver.
The prototype assumes the range-based solver gives results comparable to Z3, even if less precise.
There is no good way to model forward solving without re-running the analyzer.

What this means for readers of a verdict:

- A Bug Path that the range-based solver accepted can be unsatisfiable under Z3, because Z3 is more precise. The Baseline Verdict exists so that this case isn't blamed on the user's constraint.
- CodeChecker turns Z3 refutation on by default when Clang supports it, so the Baseline Verdict should normally be Feasible for reports it produced. Refutation can be off or inconclusive, so the check stays.
- Infeasible under Z3 doesn't prove what the forward solver would have done with the same assumption, because a forward run may have explored different paths.
- Feasible means the recorded constraints are consistent with the What-If Constraints. It doesn't prove real execution can follow the path, because the analyzer's model over-approximates things like unknown function calls.

Whether this mismatch hurts usability should be judged during the demo.

The first demo example is a function with two independent assignments of null before a dereference.
A real analyzer run produced one report for it, with the Bug Path `a == 0`, `b != 0`.
Adding `b == 0` makes that Bug Path Infeasible while the bug still exists through `a`.

Real-report candidates are FFmpeg, tmux and Vim.
If none gives a clear example, choose another project during the demo work.

2026-11-11, after the ticket 08 demo: the solver mismatch did not show up as a usability problem on the demo reports.
All 30 path-sensitive tmux 3.5a reports, analyzed with Z3 refutation on, have a Feasible Baseline Verdict when their last step's SMT-LIB goes to Z3, and none took more than 10 ms.
Both demo checks, `a == 0` on the two-path example and `flags == 0` on `grid.c:1073`, are Infeasible at a step where a forward run with the same assumption would also have stopped: there `flags` would be the constant 0 and `flags & GRID_STRING_WITH_SEQUENCES` would fold to false.
So on these examples the two solvers agree, and the Baseline Verdict box never appeared.
The demo did not test a case where Z3 refutes what the range-based solver accepted, apart from the `z3-refuted.c` fixture, so the concern stays open for paths with nonlinear arithmetic or bit tricks.
Details are in the Comments of `issues/08-demo-on-a-real-report.md`.
