# Colorful Day wiki

Historical record of the Colorful Day implementation run.
Every claim is dated, and claims about code cite a commit.
Sources such as the spec and tickets are cited here, never copied.

## Process

- [Execution plan](execution-plan.md): ticket order, what runs in parallel, when to stop for the user, the scaling pass with its lane results, trace format v2, the LLVM run, and the CFG and store pass.
- [Worker rules](worker-rules.md): constraints every ticket worker is given.

## Direction

- [Use case review](use-case-review.md): the 2026-11-12 triage study's findings on What-If against other uses of the constraint data, the lead's recommended order of next work, the mechanical pass, the Explain the path spec and tickets, and the LLVM rerun with assertions on.
- [Explain the path run](explain-the-path-run.md): ticket order, constraints, acceptance record of all ten tickets of the follow-up spec, the LLVM measurements after slices 1 and 2, and the What-If reach measured again.

## Environment

- [Dev environment](dev-environment.md): where the Clang build, venv and server state live, and why, plus environment traps and the performance evaluation.

## Design

- [Data contract](data-contract.md): how constraint data travels from Clang to the web UI.
- [Web UI decisions](web-ui-decisions.md): toggle and panel placement, line picker, What-If section, the ticket 08 visual pass, the graph view, the polish passes and the minor items still open.
