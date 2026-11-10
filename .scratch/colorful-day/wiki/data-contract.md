# Data contract between the repositories

Related: [execution plan](execution-plan.md), [dev environment](dev-environment.md).
Source: the Comments section of `../issues/02-show-ranges-for-event-steps.md`, which holds the schema.

## 2026-11-10: ticket 02

As of `llvm-project@b890c79d9a57` and `codechecker@45840c305`, Clang writes a per-diagnostic `constraint_trace` plist key, and CodeChecker stores it as a `constraint_trace` item in the report path data blob and returns it through `ReportDetails.constraintTrace`.
As of the same commits, `CodeChecker store` rewrites plists through `convert()`, so report data not written back there is lost on store.

As of `llvm-project@b890c79d9a57`, emission is opt-in through `-analyzer-config emit-constraint-snapshots=true`.
As of `codechecker@45840c305`, the API version carrying `constraintTrace` is 6.75.

## 2026-11-10: ticket 03

As of `llvm-project@320ae5fbf4ae`, each step also has `variables` and `path_condition`, `version` stays 1, and the schema is in the Comments of `../issues/03-complete-the-constraint-snapshot.md`.
As of the same commit, `path_condition` follows the crosscheck visitor's merge rule through a shared `mergeConstraintMaps`, and the per-node `ConstraintMap` is available for ticket 05's SMT-LIB.

As of the same commit, `Calling` and `Entered call` events share the CallEnter node's snapshot, so their variables are the caller's.
On 2026-11-10 the lead accepted this limit for the prototype, since the callee's parameters appear from the first event inside the call.

## 2026-11-10: ticket 04

As of `codechecker@41f307f73`, CodeChecker steps can be `kind: "control"` with `index` into `executionPath`, every step has an `order` on the Bug Path, and `version` stays 1. Details are in the Comments of `../issues/04-branch-steps-and-line-selection.md`.
As of `llvm-project@ffa40b68fbaf`, a control edge carries the snapshot of the node at its end, and a merged edge keeps its later node's snapshot.
