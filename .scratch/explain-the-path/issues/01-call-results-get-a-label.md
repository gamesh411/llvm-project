# 01: Call results get a label (tracer bullet)

**What to build:** A report reader who selects a Path Step sees a conjured symbol that is the result of a call as "result of `f()` at line N" in the Constraint Snapshot panel, with the raw symbol on hover.
This is the tracer bullet for the symbol table of `../spec.md`: Clang writes the table with an origin for conjured symbols, the report converter keeps it through store, both readers and the lit reader expose it, and the panel renders the label.
A conjured symbol Clang cannot classify reads "origin not recorded".
A trace without the table looks exactly as it does today.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] With emission on, the trace carries a per-report symbol table with one entry per atomic symbol its snapshot lists mention, giving the symbol's kind and, when the trace has SMT-LIB, its SMT-LIB term.
- [ ] A conjured symbol's entry has an origin: capped statement text, source location, callee name when the statement is a call, the stack frame it was created in, and a reason.
- [ ] The reason "call result" is written only when Clang knows it from what the analyzer recorded, and "other" otherwise. The spec's Further Notes give an unverified lead, which this ticket verifies or replaces, recording the outcome in Comments.
- [ ] The trace stays at version 2, and with emission off the plist output is byte-identical to before.
- [ ] Lit covers a call result and a symbol that must be classified "other".
- [ ] A functional test shows the stored trace keeps the table, and a stored trace without it is served as before.
- [ ] The Python and JavaScript readers expose the table through their one reader class, with unit and jest tests.
- [ ] The panel shows the label with the callee's name and line, the raw symbol on hover, and the creating function when it differs from the selected Path Step's.
- [ ] Clicking the label selects the nearest Path Step to the statement.
- [ ] Verified in a browser at 1400 and 900 pixels on the opaque-call demo and the tmux demo report, with screenshots.
