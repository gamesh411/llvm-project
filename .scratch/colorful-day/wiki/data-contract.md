# Data contract between the repositories

Related: [execution plan](execution-plan.md), [dev environment](dev-environment.md).
Source: the Comments section of `../issues/02-show-ranges-for-event-steps.md`, which holds the schema.

## 2026-11-10: ticket 02

As of `llvm-project@b890c79d9a57` and `codechecker@45840c305`, Clang writes a per-diagnostic `constraint_trace` plist key, and CodeChecker stores it as a `constraint_trace` item in the report path data blob and returns it through `ReportDetails.constraintTrace`.
As of the same commits, `CodeChecker store` rewrites plists through `convert()`, so report data not written back there is lost on store.

As of `llvm-project@b890c79d9a57`, emission is opt-in through `-analyzer-config emit-constraint-snapshots=true`.
As of `codechecker@45840c305`, the API version carrying `constraintTrace` is 6.75.
