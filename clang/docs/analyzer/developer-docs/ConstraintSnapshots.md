# Constraint Snapshots in Plist Output

The analyzer can record, for the steps of a bug path, what it knew about values at that point.
The record is called a constraint trace, and it is written into the plist diagnostic output.
It exists so that a tool reading the plist, such as CodeChecker, can show the ranges the analyzer held at each step and can ask an SMT solver questions about the path.

**The format is experimental.**
It has no stability guarantee and may change between releases without notice.
Consumers must ignore keys they do not know and must check the `version` key before reading a trace.

## Enabling it

The feature is off by default, and the plist output of an analysis that does not enable it is unchanged.
It is controlled by the analyzer option `emit-constraint-snapshots`, which is listed with its default in the {doc}`list of analyzer options <../user-docs/Options>`.

```
clang --analyze --analyzer-output plist-multi-file \
  -Xclang -analyzer-checker=core \
  -Xclang -analyzer-config -Xclang emit-constraint-snapshots=true \
  file.c
```

Only the plist output formats (`plist` and `plist-multi-file`) carry the trace.
The text, SARIF and HTML outputs ignore the option.

Through CodeChecker the option needs no new flag of its own:

```
CodeChecker analyze compile_commands.json -o reports \
  --analyzer-config clangsa:emit-constraint-snapshots=true
```

## What is emitted

Each diagnostic gets a `constraint_trace` key next to its `path`.
It holds the following, and everything is derived from the bug path of that one diagnostic:

- One snapshot for each path step that has one.
  A snapshot is taken from the analyzer node (a node of the exploded graph) the step was created at.
- The values of the variables visible at the step, as the analyzer's symbol or concrete value, and the range the analyzer holds for each symbol.
- The path condition accumulated from the start of the path up to the step.
  It only narrows along a path, so it can still mention a symbol that the analyzer no longer tracks.
- The control flow graph of each function the bug path runs through, with the blocks and edges the path took marked.
- The analyzer nodes the snapshots come from, with their kind, location and call stack.

Snapshots are stored as the change from the previous node's snapshot, and every string is stored once per diagnostic, so the trace grows with the length of the path.
The version of this encoding is the `version` key of the trace, and it is 2 at the time of writing.
The bodies of the control flow graphs are written once per plist file under the top-level key `constraint_trace_cfgs`, and a trace refers to them by index.

`clang/test/Analysis/diagnostics/Inputs/constraint_trace.py` is a reader of the format that the tests of this feature use.
The tests are the `constraint-snapshots*.c` files under `clang/test/Analysis/diagnostics/`.

## SMT-LIB and Z3

When Clang is built with Z3 (`LLVM_ENABLE_Z3_SOLVER=ON`), each snapshot also carries the SMT-LIB form of the path condition and of the variables' symbols.
The trace then has the key `smtlib` set to true.
This is what a consumer needs to decide whether the path stays feasible under extra assumptions.

Without Z3 the ranges, variables, control flow graphs and nodes are still emitted, and the SMT-LIB keys are absent.
Nothing else is lost, but a consumer cannot check assumptions against the path.
The option does not turn on Z3 refutation of reports (`crosscheck-with-z3`), which is independent of it.

## Cost

The analysis does additional work for each reported bug path, and the plist grows.
Both depend on the length of the bug paths and on how many reports a translation unit has, not on the size of the translation unit.
Printing the SMT-LIB through Z3 was the largest part of the added time in the profile taken while the feature was developed.

As one data point, the 146 translation units of tmux 3.5a produced 6.9 MB of plists with the trace in format version 2, and 1.5 MB without it.
Treat this as an order of magnitude only.
It comes from one project, one machine and one revision of the format.

Enable the option only for the runs whose reports will be read by a tool that uses it.
