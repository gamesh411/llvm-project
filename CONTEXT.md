# Colorful Day

Explaining and challenging static analyzer bug reports by showing what the analyzer assumed along a path and asking whether added assumptions keep that path possible.

## Language

**Bug Path**:
The single execution path the analyzer presents for one bug report.
_Avoid_: Report path, back path, trace

**Path Step**:
One displayed point on a Bug Path, either an event or a control-flow edge.
_Avoid_: Node, hop

**Constraint Snapshot**:
What the analyzer knew about values at one Path Step.
_Avoid_: State dump, constraint dump

**What-If Constraint**:
A temporary assumption added by the user that holds at one Path Step or throughout a Bug Path.
_Avoid_: Extra constraint, user constraint

**Path Verdict**:
The result of checking a Bug Path against What-If Constraints: Feasible, Infeasible, or Unknown.
_Avoid_: Reachability result

**Baseline Verdict**:
The Path Verdict of a Bug Path with no What-If Constraints.
_Avoid_: Initial verdict, sanity check

**Target Location**:
A source position the user selects, which can correspond to several Path Steps.
_Avoid_: Program point, which is reserved for the analyzer's internal notion
