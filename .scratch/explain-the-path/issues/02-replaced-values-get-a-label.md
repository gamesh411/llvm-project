# 02: Replaced values get a label

**What to build:** A report reader sees why the analyzer invented a value: because a call might have changed it, with the call named, or because the analyzer stopped tracking a loop.
A field of an object replaced that way reads as its access path plus the call, such as "`Tok.Kind` after `Lex(Tok)` may have changed it, line 57".

**Blocked by:** 01

**Status:** resolved

- [x] Clang writes the reasons "invalidation by a call" and "loop widening" when it knows them from what the analyzer recorded, never from statement text.
- [x] A derived symbol's entry names its parent symbol and the access path of its region.
- [x] Lit covers a value invalidated by an opaque call, a loop-widened value, and a derived field of an invalidated object.
- [x] The panel labels all three, with the invalidating call or loop linked to its nearest Path Step and the raw symbol on hover.
- [x] Reader unit and jest tests cover the new reasons and derived entries.
- [x] Verified in a browser on a demo fixture for each reason and on one LLVM report from `../../colorful-day/research/triage-study.md` whose case turned on an invalidated value (cases 1, 4 or 22).

## Comments

2026-11-12, ticket 02 worker.

Commits: `llvm-project@eb24822df6a0..acd3806439a9` and `codechecker@958c17681..9dd08b82e`.

### The rule Clang applies, verified

Verified in the analyzer source at `llvm-project@eb24822df6a0`, building on ticket 01's findings:

- `InvalidateRegionsWorker` conjures with the invalidated base region as the tag and binds it to that region, direct for a scalar and default for a record, array or symbolic region; `invalidateGlobalRegion` binds a globals memory space by default (`RegionStore.cpp`).
  A non-system call invalidates the internal globals space, and a later read of a global is `derived_` from that symbol.
- Loop widening (`getWidenedLoopState`, off unless `widen-loops=true`) calls `invalidateRegions` with no call at the block entrance of the loop's condition block, with that block's first element, so it replaces bound stack locals and arguments and bound globals one by one, not the globals space.
  The node is an untagged `BlockEntrance` whose state differs from its predecessor's; nothing else changes the state there.
- A conjured symbol's tag is not always memory: `ContainerModeling` passes string literals, `CStringChecker` and `ExprEngineCXX` their own tags. So Clang never dereferences a tag.
  `StoreManager::bindsSymbolTo`, added NFC, looks the tag up as a cluster key by address and compares the binding's region and symbol.

Rule: a conjured symbol with a tag is `invalidation` when the Bug Path has a node tagged `ExprEngine::conservativeEvalCallTag()` whose `PostStmt` statement and frame are the symbol's, and that node's store binds the symbol to the region its tag names while the node before does not.
It is `loop_widening` when its element is the first of its block, and the Bug Path has an untagged entrance of that block in its frame, with a state differing from its predecessor's, whose store binds it that way and whose predecessor's does not.
The "not before" part ties the symbol to that visit: a value replaced in an earlier pass of a loop is still bound later.
Everything else stays `other`. Nothing reads the statement's text or kind.
A checker that invalidates while modelling a call (`memcpy` under `unix.cstring`) makes a symbol of the same shape, but not at those nodes, and lit checks that it stays `other`.

The origin names the replaced region by `getDescriptiveName(false, false)`, or `globals: true` for a memory space, and the loop's start for widening. A derived entry has `parent` and `region`, and its parent gets an entry even when no list names it.

### Decisions

- A label's call is its statement when at most 32 characters, else `callee(…)`, with the whole statement in the hint. Ticket 03 owns the general shortening and can replace this.
- Labels: "`x` after `fill(&x)` may have changed it", "a global after `refresh()` may have changed it", "`hits` after the loop may have changed it" (the line is the loop's), "`r.len` of the result of `get()`", "value from `malloc(16)`"; without an access path "a value after …" or "part of `Tok` after …". The line follows a comma, as the lead asked, which changes ticket 01's "result of `f()` line N" to "…, line N".
- The label's own title is its explanation followed by the raw symbol, since an inner title hides the row's.
- An access path behind a pointer or `this` is absent (the analyzer's description has none); ticket 04 can widen `describeRegion` in `BugReporter.cpp`, which both derived entries and origins use.
- `map_trace_locations` used to map only the last listed location of a table; it now maps all, which the new `loop` needed.

### Verification

- Emission off: 18 inputs (demos and 10 tmux TUs, two runs per binary) and all 146 tmux TUs byte-identical between the pre-change binary and the new one, apart from `clang_version`. Emission on: all equal after dropping the table and its trailing strings and normalizing IDs. Script: `/Users/efulop/colorful-day-env/t02/nfc/`.
- tmux plists with `crosscheck-with-z3`: off 1,350,221 both; on 5,226,237 before, 5,329,381 after (+103,144, +2.0%). 803 entries: 239 conjured (112 invalidation, 106 call result, 21 other), 255 derived, all with a parent.
- LLVM `TokenAnnotator.cpp` (NDEBUG database of `llvm-scale`): 19 s, 478 MB RSS through `CodeChecker analyze`.
- Checks: Colorful Day lit 8 passed, 1 unsupported; `clang/test/Analysis` 1249 passed, 14 unsupported, 5 expectedly failed, 1 failed (the user's untracked `bstring-UninitRead-partial-init.c`); `sarif-multi-diagnostic-test.c` passed in 2 full runs and 15 runs of `diagnostics/`; functest 38 passed; report-converter unit 155, server unit 119, jest 54; eslint clean; pycodestyle clean, pylint 10.00, mypy clean; clang-format clean.
- Browser, `/Users/efulop/colorful-day-env/screens/`: `t02-replaced-field-1400/900.png` (report 50, "`Tok.Kind` after `lex(&Tok)` may have changed it, line 11"), `t02-opaque-call-1400/900.png` (49, globals), `t02-widened-loop-1400/900.png` (88), `t02-call-result-1400/900.png` (48, "value from `malloc(16)`, line 11"), `t02-tmux-1400/900.png` (65), `t02-llvm-case1-1400/900.png` and `t02-llvm-case1-label-click-1400.png` (86). No element overflows at either width; ticket 10 ranges and ticket 07 tags still show.
- Study case 1 (`TokenAnnotator.cpp:3452`, "was `this->Current` invalidated by the `parse()` call?"): `Current` at Step 3 reads "a value after `this->parse(prec::LogicalOr)` may have changed it, line 3486", which answers which call replaced it and that the call was not inlined. It does not name `Current`, which waits for ticket 04.

### Open points

- Compound expressions such as `(conj_$19) > (reg_$2)` still show raw (ticket 03), so the widened demo shows its label under the `hits` variable only.
- A running server keeps the report converter it started with: after a reader change, restart it before storing, or new locations are stored unmapped and the panel stays blank on `shortenPaths` of a number. The panel could be hardened against a non-string file.
- Analysis time and LLVM-run size for the slice remain ticket 03's.
