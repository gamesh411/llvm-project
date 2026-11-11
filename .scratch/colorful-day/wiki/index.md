# Colorful Day wiki

Historical record of the Colorful Day implementation run.
Every claim is dated, and claims about code cite a commit.
Sources such as the spec and tickets are cited here, never copied.

## Process

- [Execution plan](execution-plan.md): ticket order, what runs in parallel, when to stop for the user, and the scaling pass with its lane results.
- [Worker rules](worker-rules.md): constraints every ticket worker is given.

## Environment

- [Dev environment](dev-environment.md): where the Clang build, venv and server state live, and why, plus environment traps and the performance evaluation.

## Design

- [Data contract](data-contract.md): how constraint data travels from Clang to the web UI.
- [Web UI decisions](web-ui-decisions.md): toggle and panel placement, line picker, What-If section, the ticket 08 visual pass, the graph view and queued UI problems.
