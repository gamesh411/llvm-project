# 01: Call results get a label (tracer bullet)

**What to build:** A report reader who selects a Path Step sees a conjured symbol that is the result of a call as "result of `f()` at line N" in the Constraint Snapshot panel, with the raw symbol on hover.
This is the tracer bullet for the symbol table of `../spec.md`: Clang writes the table with an origin for conjured symbols, the report converter keeps it through store, both readers and the lit reader expose it, and the panel renders the label.
A conjured symbol Clang cannot classify reads "origin not recorded".
A trace without the table looks exactly as it does today.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] With emission on, the trace carries a per-report symbol table with one entry per atomic symbol its snapshot lists mention, giving the symbol's kind and, when the trace has SMT-LIB, its SMT-LIB term.
- [x] A conjured symbol's entry has an origin: capped statement text, source location, callee name when the statement is a call, the stack frame it was created in, and a reason.
- [x] The reason "call result" is written only when Clang knows it from what the analyzer recorded, and "other" otherwise. The spec's Further Notes give an unverified lead, which this ticket verifies or replaces, recording the outcome in Comments.
- [x] The trace stays at version 2, and with emission off the plist output is byte-identical to before.
- [x] Lit covers a call result and a symbol that must be classified "other".
- [x] A functional test shows the stored trace keeps the table, and a stored trace without it is served as before.
- [x] The Python and JavaScript readers expose the table through their one reader class, with unit and jest tests.
- [x] The panel shows the label with the callee's name and line, the raw symbol on hover, and the creating function when it differs from the selected Path Step's.
- [x] Clicking the label selects the nearest Path Step to the statement.
- [x] Verified in a browser at 1400 and 900 pixels on the opaque-call demo and the tmux demo report, with screenshots.

## Comments

2026-11-12, ticket 01 worker.

Commits: `llvm-project@c8ffa734edc1..16d93c4c130c` and `codechecker@00362f60c..958c17681`.

### How the analyzer conjures, and the rule Clang applies

Verified in the analyzer source at `llvm-project@38e11c720645`:

- A call the analyzer does not inline ends in `ExprEngine::conservativeEvalCall`, which invalidates the call's regions, then `bindReturnValue` conjures the return value with `conjureSymbolVal(Elem, SF, ResultTy, Count)`, which has no tag (`ExprEngineCallAndReturn.cpp`).
  Its node is tagged "ExprEngine : Conservative eval call".
- Region invalidation conjures with the invalidated base region as the tag, at the same element, frame and count as the call (`RegionStore.cpp`, `InvalidateRegionsWorker` and `invalidateGlobalRegion`, the latter with the globals memory space as the tag).
  So a value replaced by a call and that call's result differ only by the tag.
- Loop widening calls `invalidateRegions` on the stack locals, stack arguments and globals memory spaces (`LoopWidening.cpp`), with the first element of the loop's block as the element, so it conjures through the same invalidation code, with region tags.
- The lead's "a call result has no tag" is true but not sufficient: many other places conjure without a tag too (`ExprEngineC.cpp` for unknown operator results and casts, `ExprEngineCXX.cpp`, `ExprEngine.cpp`), and a checker that evaluates a call conjures its return value with `conjureSymbolVal(Call, C.blockCount())`, which is the same element, frame, type, count and null tag as the analyzer's own.
  MallocChecker's `malloc` is one, and the symbol alone cannot tell it apart from a call result.

Rule Clang now applies: a conjured symbol is `call_result` when, on the bug path, there is a node whose program point is a `PostStmt` tagged with `ExprEngine::conservativeEvalCallTag()`, and the value bound to that statement in that node's frame is the symbol, the symbol has no tag, and its statement and frame are that node's.
Every other conjured symbol is `other`.
No reason is read off the statement's text or kind.

For ticket 02: invalidation symbols carry the region as their tag, and both the invalidating call and loop widening are visible on the path (the conservative eval node of the call, and the widened block entrance), so the same path walk can classify them without guessing.

### Decisions

- The table is a list of dicts rather than arrays, since it has one entry per symbol rather than per node and later tickets add optional keys (parent, access path, display name).
  Kind and reason are plain strings, other texts are `strings` indices.
- A symbol's frame is written as an index into `stack_frames` when that frame has a node there, and the function name always.
  A conjured symbol is often made in a callee the diagnostic pruned, whose frame has no entry, and adding it to `stack_frames` would have changed an existing key.
- Only symbols in list positions and the atoms of symbolic expressions get an entry; a `derived_` symbol's parent does not yet (ticket 02 needs it for derived labels).
- Statement text is printed with `printPretty` on one line and cut at 120 bytes with "...".
- Unknown reasons read as `other` in both readers, so ticket 02 can add reasons without breaking them.
- A malformed table makes the trace malformed in the report converter, as any other malformed part does.
- `files` can gain a statement's file nothing else names; it is added after the diagnostic's `ExecutedLines` files, so every existing file index is unchanged.
- The opaque-call demo's trace has only `derived_` symbols (its call returns void), so it shows no label until ticket 02. For a clear fixture this ticket added `demo/call-result.c` (fixtures `call_result` and `no_symbols`).
- The label's line selects the step whose node is in the origin's file, in its frame when the frame has steps, at the closest line, earliest on ties.
- In the accumulated path condition the change tag now sits beside the range, which fixed the wrap the lead noted after ticket 07.

### Verification

- With emission off, 17 inputs (the 7 demo files and 10 tmux TUs, two runs per binary) and all 146 tmux TUs are byte-identical between the pre-change binary (copied before the rebuild) and the new one, apart from the `clang_version` revision string.
- With emission on, the same 17 and 146 plists are equal after dropping `symbols`, cutting `strings` and `files` to the old length (no file was appended), and normalizing node, state, symbol, LocationContext and statement IDs. Without that normalization 6 of 17 differ, and they differ between two runs of the old binary as well.
- tmux, Clang-written plists with `crosscheck-with-z3`: off 1,350,221 bytes both; on 4,991,542 before and 5,226,320 after (+234,778, +4.7%). 28 of 29 traces have a table, with 704 entries, of which 140 are conjured: 106 call results and 34 `other`.
- Checks: Colorful Day lit 8 passed, 1 unsupported; `clang/test/Analysis` 1249 passed, 1 failing (the user's untracked `bstring-UninitRead-partial-init.c`); `sarif-multi-diagnostic-test.c` failed once in the first of three full runs and not in 12 more runs of `diagnostics/`, cause not found, and this change does not touch SARIF output. functest 35 passed, report-converter unit 155 passed, server unit 119 passed, jest 44 passed (33 in ConstraintTrace.test.js), eslint clean, pycodestyle, pylint 10.00 and mypy clean.
- Browser screenshots, report IDs of the demo workspace: `t01-call-result-1400.png` and `-900.png` (report 15), `t01-tmux-1400.png` and `-900.png` (grid.c:1073, report 31, `buf` reads "result of xmalloc() line 1057"; clicking selects the arrow reaching line 1056, `t01-tmux-label-click-1400.png`), `t01-opaque-call-1400.png` and `-900.png` (report 16), and `t01-tmux-imsg-other-symbols-1400.png` (imsg.c:424, labels in Other symbols).

### Open points

- A call result made in a pruned callee links to the nearest step by line in the file, which is not its call site (in `call-result.c`, "line 8" selects Step 1 at line 12, not line 14). Writing the innermost listed frame's call site into the origin would fix that.
- imsg.c:424 shows two `close()` results at line 447, the case ticket 03 marks.
- Analysis time and the LLVM run were not measured; the spec asks for them per slice, in ticket 03.

