Status: ready-for-agent

# Explain the path: say where each constraint came from and what it is about

Follows `.scratch/colorful-day/spec.md`.
Evidence: `.scratch/colorful-day/research/triage-study.md`.
Recommendation it implements: `.scratch/colorful-day/wiki/use-case-review.md`.
Vocabulary: `CONTEXT.md` at the repository root.

## Problem Statement

A report reader who opens a Constraint Snapshot on real C++ code mostly sees analyzer symbols that mean nothing to them.
On the LLVM run of 2026-11-12, the panel named 9% of the entries on the final accumulated path condition, and a What-If Constraint could reach 11%.
Almost half of the symbols are conjured values, and all the reader gets for them is a statement ID.
The reader cannot tell whether such a value is the result of a call, a value the analyzer invented because a call might have changed something, or a value from a loop it stopped tracking.

The most common question in 30 hand-triaged reports was "where did this value come from", and the second was "does the analyzer know these two facts belong together".
Neither the panel nor a What-If Constraint answers them today.

Three quarters of bugs end inside an inlined callee, while most constraints are added in the callers.
The panel shows only the variables of the function the selected Path Step is in, so a third of reports show no variable at all at the last Path Step.

More than a quarter of path condition changes happen at a branch that has no event on the Bug Path, so the reader never sees that an assumption was made there.

Finally, the reader has no summary of what the Bug Path demands of the outside world, and no concrete example of inputs that follow it.

## Solution

Clang records, for every symbol a Constraint Snapshot mentions, where it came from and what it stands for.
CodeChecker shows that as a readable label in place of the raw symbol, and keeps the raw symbol one hover away.

A conjured value reads as, for example, "result of `getToken()` at line 42" or "`Tok.Kind` after `Lex(Tok)` may have changed it, line 57".
A field or element value reads as its access path, such as `Builder.InsertPt.Block`.
Two different values that came from calls with the same text are marked as different, so the reader sees that the analyzer does not connect them.

The panel shows the variables of the calling functions too, grouped by function, at every Path Step.
A What-If Constraint can be written on any of these names.

The panel highlights what changed at the selected Path Step, and Path Steps that changed the path condition without an event are marked.

A new "This path requires" section lists the whole accumulated path condition of the Bug Path grouped by origin: entry inputs, call results, values replaced after a call or a loop, and the rest.
Each row links to the Path Step that set it.
On request the server adds one concrete example value for every row, taken from a Z3 model of the path, so the reader can see one set of inputs and call results that follows the Bug Path.

The work has three slices, delivered in this order: symbol origin, names, then the requires list with the example.

## User Stories

Symbol origin:

1. As a report reader, I want a conjured symbol labelled with the text of the statement that produced it, so that I don't have to decode a statement ID.
2. As a report reader, I want that label to give the line of the statement and to select the nearest Path Step when I click it, so that I can read the code that produced the value.
3. As a report reader, I want to see whether a conjured value is the result of a call, so that I know the analyzer could not see inside that call.
4. As a report reader, I want to see whether a value was replaced because a call might have changed it, and which call, so that I can judge whether that call really can change it.
5. As a report reader, I want to see whether a value was replaced because the analyzer stopped tracking a loop, so that I know the loop's real effect is not modelled.
6. As a report reader, I want an honest "origin not recorded" label when Clang cannot classify a conjured value, so that I am never shown a guess.
7. As a report reader, I want a field of a replaced object labelled with the field's access path and the call that replaced the object, so that derived symbols are readable.
8. As a report reader, I want two symbols on the Bug Path that came from calls with the same text marked as different values of the same call, so that I can see when the analyzer does not know that two calls return the same thing.
9. As a report reader, I want the callee's name shown for a call result, so that I recognize an accessor such as `size()` or `getKind()` at a glance.
10. As a report reader, I want the function the value was created in shown when it is not the function of the selected Path Step, so that I know where to look.
11. As a report reader, I want the raw symbol on hover, so that nothing is hidden from a reader who knows the analyzer.
12. As a report reader, I want a compound symbolic expression rendered from the labels of its parts, so that `(conj_$5) + 1` reads as "result of `size()` + 1".
13. As a report reader, I want long statement text shortened with the full text on hover, so that the panel stays readable.
14. As a report reader of a report stored before this feature, I want the panel to look as it did, so that old data stays usable without a re-store.
15. As an analyzer developer, I want the origin data written only when constraint emission is on, so that normal output is unchanged.
16. As an analyzer developer, I want the origin data in the lit-tested plist, so that a change in how the analyzer conjures symbols is caught by a test.

Names:

17. As a report reader, I want a symbol that stands for the initial value of a field or element shown by its access path, so that `reg_$5<... Builder.InsertPt.Block>` reads `Builder.InsertPt.Block`.
18. As a report reader, I want a symbol behind a pointer parameter shown as the pointee expression, such as `*p` or `p->len`, so that I recognize it from the source.
19. As a report reader, I want `this->field` values named, so that member functions are as readable as free functions.
20. As a report reader, I want the variables of every calling function at each Path Step, so that the panel is not empty inside an inlined callee.
21. As a report reader, I want those variables grouped under their function and call site, with the current function first, so that I can tell `n` in the caller from `n` in the callee.
22. As a report reader, I want caller groups collapsed by default when there are many, so that a deep call stack does not bury the current function.
23. As a report reader, I want the accumulated path condition to use these names, so that the rows I care about are named there as well.
24. As a report reader, I want the line picker to keep telling visits of a line apart using the names it has, so that naming does not make two picker rows look the same.
25. As a report reader, I want to write a What-If Constraint on a caller's variable, so that I can test a claim about the function that made the call.
26. As a report reader, I want to write a What-If Constraint on an access path such as `gl->cellsize` or `this->Current`, so that I can test a claim about a field.
27. As a report reader, I want the What-If suggestions to offer every name I can constrain at the selected Path Step, so that I don't have to guess the spelling.
28. As a report reader, I want a clear Unknown verdict when a name exists in several calling functions and I did not say which, so that my constraint is never applied to the wrong one.
29. As a report reader, I want to pick the function from the suggestion list when a name is ambiguous, so that I can resolve it without new syntax to learn.
30. As a report reader, I want "Holds throughout the path" to work on access paths, so that "this field is never null" is one constraint.
31. As an analyzer developer, I want names to be labels and never identifiers, so that two symbols with the same name stay two rows.

What changed, and what the path requires:

32. As a report reader, I want the entries that changed at the selected Path Step highlighted, so that I see what this step did without comparing two steps by eye.
33. As a report reader, I want Path Steps that changed the path condition without an event marked in the report tree and in the source, so that I notice assumptions the Bug Path does not describe.
34. As a report reader, I want a "This path requires" section listing the whole path condition of the Bug Path, so that I can ask which requirement is unrealistic.
35. As a report reader, I want those requirements grouped as entry inputs, call results, replaced values and other, so that I can start with the group I can judge fastest.
36. As a report reader, I want each requirement to link to the Path Step that set its final range, so that I can go to the code that made the assumption.
37. As a report reader, I want each requirement to say which function that Path Step is in, so that I can spot an assumption made deep inside a callee.
38. As a report reader, I want requirements on entry inputs listed first, so that I can answer "can a real caller produce this" from one list.
39. As a report reader, I want to ask for a concrete example, so that I see one set of values that follows the Bug Path.
40. As a report reader, I want the example to give a value for every requirement, including call results, so that hidden premises such as "`f()` returned 0" are explicit.
41. As a report reader, I want the example labelled as one of many, so that I do not read it as the only way to reach the bug.
42. As a report reader, I want the example to respect my What-If Constraints, so that I can see an example under my own assumptions.
43. As a report reader, I want a plain message when the solver cannot produce an example in time, so that the page never waits indefinitely.
44. As a report reader, I want no example offered when the report has no solver input, with the reason, so that I know what is missing.
45. As a report reader, I want pointer examples shown as null or non-null, so that I am not shown a meaningless address.
46. As a report reader, I want example values kept only in the open report page, so that an example is never mistaken for a stored fact.

Across slices:

47. As a CodeChecker administrator, I want no database migration, so that enabling this needs only new analysis runs.
48. As a CodeChecker user, I want no new CLI flag and no new analyzer option, so that the existing `emit-constraint-snapshots` passthrough turns all of it on.
49. As a project owner, I want the size and time cost measured on the LLVM run before the slice is accepted, so that the feature stays usable at that scale.
50. As a project owner, I want the triage study's naming table measured again after slices 1 and 2, so that the improvement is a number.
51. As a docs reader, I want the two documentation pages updated in the slice that changes what they describe, so that they never describe an older panel.

## Implementation Decisions

Trace format:

- The trace stays at version 2, and everything new is additive, relying on the existing rule that consumers ignore keys they do not know.
  A version bump was rejected because it would disable every stored trace, as the move to version 2 did.
- A trace gains a per-report symbol table.
  It has one entry per atomic symbol that any snapshot list of the trace mentions, keyed by the symbol's dump string in the trace's string table.
- A symbol entry carries the symbol's kind (region value, conjured, derived, metadata, extent), a display name when Clang can form one, its SMT-LIB term when the trace has SMT-LIB, and for conjured symbols an origin.
- An origin carries the statement's printed text, its source location, the callee's name when the statement is a call, the stack frame it was created in, and a reason.
- The reason is one of: call result, invalidation by a call, loop widening, other.
  Clang decides it from what the analyzer recorded when it made the symbol, and writes "other" whenever it cannot tell.
  It never infers a reason from the statement text.
- A derived symbol entry names its parent symbol and the access path of its region, so the UI builds its label from the parent's origin.
- Display names come from the analyzer's own descriptive naming of memory regions.
  A region the analyzer cannot describe gets no name, and the UI falls back to the origin label or the raw dump.
- Compound symbolic expressions get no entry. The UI renders them from the entries of their atoms.
- Statement text is capped in length in the trace, since it is a label and the source is one click away.
- Variables of calling frames go in a new snapshot list next to the existing `variables` list, with the frame as part of each entry, encoded as deltas like the other lists.
  The existing `variables` list keeps its shape and its meaning, the variables of the node's own frame, so existing readers are untouched.
- Reading a caller's variables creates analyzer symbols the first time a parameter or global is read, as recorded for the existing variables on 2026-11-11.
  This is accepted with emission on. With emission off the analyzer's output must stay byte-identical.
- Both readers, Python and JavaScript, expose the symbol table and the caller variables through the one reader class each language has. No consumer reads the raw keys.

CodeChecker server and API:

- Slices 1 and 2 need no Thrift change, because the trace travels as one opaque value.
- What-If name resolution moves from "a variable of the step's frame" to "any name the reader can see at that step with an SMT-LIB term": variables of any frame, and symbol display names.
- The What-If grammar gains access paths on the left side of a comparison, made of identifiers, `.`, `->`, `*` and constant subscripts, matched as text against display names. It is not parsed as C.
- A name that resolves to more than one symbol at the step gives an Unknown verdict naming the candidates.
  A frame-qualified form chosen from the suggestion list resolves it.
- The example is part of the What-If result: a check whose verdict is Feasible can return one model of the path with the What-If Constraints applied, as a list of symbol and value pairs.
  It is returned only when the client asks for it, so ordinary checks cost what they cost today.
  Checking with no What-If Constraints gives the example for the Bug Path as recorded.
- The example uses the existing per-call solver time limit, and a timeout yields no example with a reason. It does not change the verdict.
- This adds optional fields to the What-If request and result and raises the API minor version once.
- Nothing about an example or a What-If Constraint is stored.

Web UI:

- A symbol's label replaces its raw dump wherever the panel, the picker, the requires list or the CFG and States views show a symbol, with the raw dump on hover.
- Labels are never used as keys. Rows stay keyed by symbol.
- The Variables section becomes one group per stack frame, current frame first and expanded, callers after it and collapsed when there are more than a few.
- "Changed here" highlighting compares the selected Path Step's snapshot with the one before it, using the deltas the trace already has.
- A Path Step that changes the path condition and is a control step with no event on its node gets a marker in the report tree and on its place in the source.
- "This path requires" is a section of the panel that does not depend on the selected Path Step. It reads the snapshot of the last Path Step.
- Its groups come from the symbol table: entry inputs are region values rooted in a parameter of the outermost frame, a global or the outermost `this`; call results are conjured symbols with that reason; replaced values are invalidation and widening symbols and symbols derived from them; everything else is "other".
- Each row links to the last Path Step whose node changed that entry.
- The example appears as a column of that section after the reader asks for it, and is dropped when the What-If list changes, since it no longer matches.

Order and acceptance:

- Slice 1 is symbol origin in Clang, both readers, and the labels.
- Slice 2 is display names, caller variables, and What-If on those names.
- Slice 3 is change highlighting, silent-change markers, the requires list and the example.
- Each slice is accepted on the two-path demo, the tmux demo report and at least three LLVM reports from the triage study, chosen for the question the slice serves: for slice 1 a case where two unrelated symbols share call text, for slice 2 a case whose deciding constraint was unnamed, for slice 3 a case decided by entry inputs.
- Each slice reports plist size and analysis time on the LLVM run against the figures of 2026-11-12.
- After slice 2 the triage study's table A4 is measured again with the study's own scripts.

## Testing Decisions

A good test exercises behavior through a public boundary and does not depend on how the data gets built.
The seams are the ones the first spec set up. No new seam is added.

- Clang seam: lit tests run the analyzer with the option on and check the plist through the existing lit trace reader.
  New cases: a call result, a value invalidated by an opaque call, a loop-widened value, a derived field of an invalidated object, a symbol Clang must classify as "other", access-path names for fields, pointees and `this`, caller variables inside an inlined callee, and byte-identical output with the option off.
  Prior art: the existing constraint snapshot lit tests and their Z3-gated variants.
- CodeChecker seam: functional tests store a fixture plist and call the Thrift API.
  New cases: the stored trace keeps the symbol table and caller variables; What-If on a caller's variable; What-If on an access path; an ambiguous name gives Unknown with candidates; a Feasible check returns an example when asked and none when not; an example under a What-If Constraint satisfies it; a trace without the new keys behaves as today.
  Prior art: the existing What-If functional tests and the What-If server unit tests, including the patched-solver timeout test.
- The fixture plist is produced by the Clang build, so it stays the contract between the repositories.
- The JavaScript reader gets jest tests for the symbol table, label rendering of atoms and compound expressions, frame grouping and the requires grouping.
  Prior art: the existing jest tests of the reader and the path-shortening helper.
- The Python reader's unit tests cover the same reading on the server side.
- The web UI is verified in a real browser against a live server at 1400 and 900 pixels, with screenshots reviewed by the lead, on the acceptance reports named above.

## Out of Scope

- Non-constraint analyzer state: checker state such as heap ownership, dynamic type information and store contents. Four study cases needed it, and it is a separate, larger piece.
- Why a call was not inlined.
- Detecting correlations for the reader. The feature shows that two values are unrelated, and does not suggest that they should be related.
- Comparing two variables, arithmetic, or `||` in a What-If Constraint.
- Asserts compiled out by `NDEBUG`. The remedy is analyzing with assertions on.
- Readable ranges such as "not 0", and the tooltip that stays open, which are a separate ticket.
- Bug-level answers, re-running the analyzer, and saving or sharing anything a reader typed or was shown.
- A minimal set of requirements the bug hinges on, such as an unsatisfiable core.
- Upstream submission and production hardening.

## Further Notes

Figures in the Problem Statement are from `.scratch/colorful-day/research/triage-study.md`, measured on 2026-11-12 on one C++ project with assertions compiled out, by one triager.
An LLVM run with assertions on was started on 2026-11-12 and may shift them.

A lead for the implementer of the reason field, not verified against the code: the analyzer conjures a call's result without a symbol tag, while region invalidation conjures with the invalidated region as the tag, and loop widening goes through invalidation with the loop statement.
If that holds, the tag and the statement's kind separate the three reasons without any guessing.
Checker-modelled functions conjure in their own ways and are the expected source of "other".

The label of a call result states that the analyzer could not see inside the call.
It does not say why, which is out of scope above.

An example is a model of what the analyzer recorded.
It is not proof that a real execution can follow the Bug Path, for the same reasons the first spec gives for a Feasible verdict.
The wording in the UI has to carry that.

The largest trace of the LLVM run has 186 stack frames.
Caller variables are delta-encoded and change rarely while a callee runs, so the expected cost is one entry per variable per frame, but this is the size risk of slice 2 and is the reason each slice reports sizes.
