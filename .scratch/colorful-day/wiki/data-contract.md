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

## 2026-11-10: ticket 05

As of `llvm-project@2b6fae011b13`, each snapshot carries SMT-LIB built with the Z3 crosscheck's symbol encoding, and as of `codechecker@c8bb766cb` the server answers `checkWhatIf` (API 6.76) with Python Z3, using a 2000 ms timeout per solver call (`WHAT_IF_SOLVER_TIMEOUT_MS`) and two calls per check.
The "two calls per check" part is superseded by the ticket 07 entry below, as of `codechecker@6325f9164`.
The no-Z3 path was verified only by a CodeChecker fixture without SMT-LIB and by compiling `BugReporter.cpp` with Z3 off, since `constraint-snapshots-no-z3.c` is unsupported on the Z3 build. Details are in the Comments of `../issues/05-first-what-if-constraint-and-verdict.md`.

## 2026-11-10: ticket 06

As of `codechecker@da8c060ca` (API 6.77), the request is still a list of `{pathStep, expression}`, and `WhatIfResult` gained an optional `syntaxError {constraintIndex, message, offset}` and an optional `reasonConstraintIndex`. Details are in the Comments of `../issues/06-full-what-if-input-and-unknown.md`.
On 2026-11-10 the lead decided to keep the solver timeout covered by a unit test only, rejecting a test-only server hook, as recorded in that ticket's Comments.

## 2026-11-10: ticket 07

As of `codechecker@6325f9164` (API 6.78), What-If Constraints carry an optional "holds throughout" flag, and the server finds the first dead step by binary search over the steps. That is at most 2 + ceil(log2 N) solver calls of up to 2000 ms each plus a 4000 ms search budget, so about 8 s per check at worst. The rules are in the Comments of `../issues/07-holds-throughout-and-first-dead-step.md`.
The binary search relies on the accumulated path condition only narrowing along a path. If the solver gives up mid-search, the named step is proven dead but may be later than the true first.
On 2026-11-10 the lead accepted mapping the server's earliest `order`, often the edge into an "Assuming" line, to that line's event in the UI, consistent with line selection.

## 2026-11-11: ticket 08

As of `codechecker@e78323748` (API 6.79), `WhatIfResult` also has `8: optional bool firstDeadStepIsEarliest`, set with `firstDeadStep`, false when the search ran out of budget or the solver gave up on a step. A missing flag reads as earliest in the UI.

## 2026-11-11: ticket 09

As of `llvm-project@73b1d83878a8` and `codechecker@b31cdd260`, `constraint_trace.cfgs` holds each Bug Path function's control flow graph once per report, each step has a `cfg_position`, and `version` stays 1. Details are in the Comments of `../issues/09-stretch-cfg-side-view.md`.
The ticket 09 worker measured tmux demo plists at 23,053,531 bytes, against 17,174,536 after ticket 08 and 1,481,363 with emission off. That is 15.6 times the off size, and most of the graph data's share is plist XML overhead.

## 2026-11-11: ticket 10

As of `llvm-project@11efdf0713b6` and `codechecker@06fde7aaa`, the trace also carries the analyzer nodes that Path Steps came from, with their calling context and location, and there is no API change. The ticket 10 worker measured tmux plists growing by 437,861 bytes over ticket 09, to 15.9 times the off size.
As of the same commits, trace `location.file` and `call_site.file` are plist file indices in Clang's output and full paths in `ReportDetails.constraintTrace`, and `--trim-path-prefix` does not apply to them. On 2026-11-11 the lead assigned that to a cleanup worker.
The `--trim-path-prefix` part is superseded by the trace paths entry below, as of `codechecker@333e8467d`.

## 2026-11-11: trace paths and `--trim-path-prefix`

As of `codechecker@333e8467d`, `Report.trim_path_prefixes` also trims the `location.file` and `call_site.file` paths in the constraint trace, so they match the stored `filePath` of the report's events.

## 2026-11-11: wiki lint corrections

The worst-case figure in the ticket 07 entry above is superseded in its wording: as of `codechecker@6325f9164`, the Baseline and verdict calls take up to 2000 ms each, and the first dead step search is capped by its 4000 ms budget, so a check takes at most 8 s.
The source is the Comments of `../issues/07-holds-throughout-and-first-dead-step.md`.
