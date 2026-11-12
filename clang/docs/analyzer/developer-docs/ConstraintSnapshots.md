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
- A table of the symbols the snapshots mention, and the types of the symbolic expressions they constrain, described below.

Snapshots are stored as the change from the previous node's snapshot, and every string is stored once per diagnostic, so the trace grows with the length of the path.
The version of this encoding is the `version` key of the trace, and it is 2 at the time of writing.
The bodies of the control flow graphs are written once per plist file under the top-level key `constraint_trace_cfgs`, and a trace refers to them by index.

`clang/test/Analysis/diagnostics/Inputs/constraint_trace.py` is a reader of the format that the tests of this feature use.
The tests are the `constraint-snapshots*` files under `clang/test/Analysis/diagnostics/`.

## Where a symbol came from

The trace's `symbols` key has one entry for each atomic symbol that the snapshots mention, alone or inside a symbolic expression, such as `conj_$5{int, LC1, S1234, #1}` in `(conj_$5{int, LC1, S1234, #1}) + 1`.
An entry gives the symbol's kind, its type, and, with Z3, its SMT-LIB term.
The type is the canonical type without qualifiers, such as `unsigned long` for a `size_t`, and the entry says whether the analyzer treats the symbol as an address.
A reader needs both for symbols whose dump does not start with their type, such as a derived one: they say whether a range is null and how wide an integer is.
A symbolic expression has no entry there, since a reader renders it from its atoms, but its range needs a type that no atom has.
So the trace's `expressions` key gives the type, and whether it is an address, of each symbolic expression the path condition constrains or a variable holds, such as `unsigned long` for `(reg_$0<unsigned long mask>) & 7U`.
A region value, the initial value of a region, has a name: the access path of its region, such as `p->len` for `reg_$2<int SymRegion{reg_$1<struct S * p>}.len>`.
A symbol the analyzer conjured also has an origin: the statement it was made for, with its location and the called function's name when the statement is a call, the function it was made in, and a reason.

The reason is `call_result` when the symbol is the value a call returned and the analyzer evaluated that call without seeing inside the callee.
The analyzer does not record this on the symbol, which a checker modelling the call makes in the same way.
Clang tells them apart by the node the analyzer's conservative evaluation of a call ends in: a symbol bound to the call there is the call's result.
The reason is `invalidation` when the symbol is the new value of memory such a call may have changed.
Invalidation conjures with the replaced memory as the symbol's tag, at the call's statement, frame and visit, so the symbol looks like the call's result except for the tag.
Clang gives this reason only when, at the node the analyzer's conservative evaluation of that call ends in, the store binds the symbol to the memory its tag names and the node before does not.
The reason is `loop_widening` when the analyzer stopped following a loop and replaced the function's memory at the entrance of the loop's condition block, which it does under `-analyzer-config widen-loops=true`.
Clang gives this reason only when the symbol was made for the first element of that block and the store binds it anew at that block's entrance on the bug path.
For both, the entry names the replaced memory as an access path, such as `Tok`, or says that the call replaced every global, and for loop widening it gives the loop's location.
Checkers that model a call replace memory with symbols of the same shape, but not at those nodes, so their symbols stay `other`.
Every other conjured symbol has the reason `other`, including a value a checker made for a call it models, such as `malloc` under `unix.Malloc`.
Clang never infers a reason from the statement's text.

A symbol derived from another one, such as the field `Tok.Kind` of the value that replaced `Tok`, names that parent symbol and the access path of its own region.
The parent has an entry of its own even when no list mentions it, so a reader can label the field from the parent's origin.
An access path is the expression a reader would write for the region, built from what the analyzer knows about it: variables, fields, `this`, elements of arrays with a constant index or one a variable holds, and the pointee of a pointer whose own value is the initial or replaced value of named memory, written `*p`, `p[2]` and `p->len`.
Memory the analyzer reads as another type than its pointer's is named through a cast, such as `((struct S *)data)->len`.
A base class and an anonymous struct or union are left out, as in the source.
The path is absent when any part of the region has no such description, for example the pointee of a call's result, memory read as another type than its own, or an element at a computed index, and Clang never makes one up from the symbol's dump.
Region value names, derived symbols' regions and the memory an invalidation replaced are described the same way, so `this->Current` after `this->parse()` names the field.
An extent, the unknown size of some memory, names that memory the same way, such as `*l->cells`.
Consumers must treat a reason they do not know as `other`, because more reasons may be added.

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
