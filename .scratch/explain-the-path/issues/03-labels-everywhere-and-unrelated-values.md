# 03: Labels everywhere, and unrelated values of the same call

**What to build:** Symbol labels appear wherever a symbol is shown, and a report reader can see when the analyzer treats two calls with the same text as returning unrelated values.
This ticket closes slice 1 of `../spec.md`.

**Blocked by:** 02

**Status:** resolved

- [x] A compound symbolic expression renders from the labels of its atoms, such as "result of `size()` + 1", with the raw dump on hover.
- [x] The line picker, the CFG view and the States view use labels where they show a symbol.
- [x] Two symbols on the Bug Path whose origins are calls with the same statement text are each marked as a different value of the same call, with a link to the other's Path Step.
- [x] Long statement text is shortened, with the full text on hover.
- [x] Labels are never used as row keys, and two symbols with the same label stay two rows. A jest test covers this.
- [x] Slice acceptance in a browser at 1400 and 900 pixels: the two-path demo, the tmux demo report, and three LLVM reports from the triage study, one of them a case where two unrelated symbols share call text (cases 2, 10 or 12).
- [x] Plist size and analysis time on the LLVM run are reported against the 2026-11-12 figures in `../../colorful-day/wiki/execution-plan.md`.
- [x] Both documentation pages describe the labels.

## Comments

2026-11-12, ticket 03 worker.

Commits: `llvm-project@e7de190f44c3` (Clang), `cb50e467f977` (trace format doc, demo, dev loop); `codechecker@df256f397..7457ff20c`.

### Decisions

- Type of a symbol: the trace's symbol entry gains `type` (canonical, unqualified, as the analyzer would print it) and `pointer` (true when `Loc::isLocType`).
  Chosen over a bare pointer flag because the type also gives derived symbols and typedefs (`size_t`) their integer width, which ticket 10's readable ranges need, and ticket 04 can name types from it.
  Cost is two integers per entry and the type strings.
  Readers without it fall back to the dump.
  Emission off: 20 of 20 inputs and 146 of 146 tmux TUs byte-identical to the pre-change binary (two runs each, apart from the revision string); emission on: equal after dropping the table (`/Users/efulop/colorful-day-env/t03/`).
- Compound expressions: a small structural parser (`parseSymbolExpression`) reads `(L) op R`, `N op (R)`, casts `(T) (X)` and unary operators with balanced brackets, and renders from atom labels; a region value atom is named by the variable that held it, else by the last word of its region.
  Any atom without a label or name, or any text not read to the end, shows the whole raw dump (for example extents and `Element{...}` regions).
  Brackets are kept only where an operator sits inside a different one, a cast or a minus.
- Same-call marker: only symbols whose reason is `call_result` and whose statement text is equal and not cut by Clang (ends in "...").
  Invalidation and `other` symbols are not marked: they are not "the value of the call".
  The tag reads "another `DestTy->isRealFloatingType()` result, Step 4"; with more, the nearest is named, "+N" follows and the title lists all.
- Shortening: one `shortenStatement` for the labels and the tag, 40 characters; a longer call keeps its outermost callee with receiver and drops arguments (`this->parse(…)`), else the callee name, else a cut.
  It replaces ticket 02's 32-character stopgap.
  A call result without a callee name is now shortened too, and its hover names the call.
- `nearestStep` (used by label clicks and the tag's link) now ties by column before the earliest step, and prefers an event over an arrow into it, so two calls on one line link to different steps.
- The CFG and States views show source text and states, never a symbol, so they have no label to show.
  The picker (which both open) uses ranges in words with pointers as null or non-null, and its hover adds the value's label.
- Panel rows moved to `SnapshotRows.js` so that keys can be tested: key is the variable name or symbol dump, never a label.
- Unmapped file hardening: `shortenPaths` takes text only and `labelPlace` writes "line N" without the file for a non-path file.

### Verification

- Checks: Colorful Day lit 9 passed, 1 unsupported; `clang/test/Analysis` 1250 passed, 14 unsupported, 5 expectedly failed, 1 failed (the user's untracked `bstring-UninitRead-partial-init.c`; `func-mapping-test.cpp` needs `clang-extdef-mapping` rebuilt after a Clang rebuild, then passes); functest 39 passed; report-converter unit 155, server unit 119; jest 85 (SnapshotRows 6, ConstraintTrace 79); eslint clean; pycodestyle clean, pylint 10.00, mypy clean; clang-format clean.
- Browser, `/Users/efulop/colorful-day-env/screens/`, 1400 and 900 px, no element overflows after fixing the tag (it overflowed its column at first and now wraps): `t03-two-path-*`, `t03-same-call-*`, `t03-widened-loop-*` ("`hits` after the loop may have changed it > `n`"), `t03-tmux-*` (grid.c:1073, `buf` reads "result of xmalloc(), line 1057", `gd` non-null), `t03-tmux-accumulated-1400`, `t03-picker-1400`, `t03-states-1400`, and the LLVM cases below.
- LLVM cases, re-analyzed alone with the current Clang from the NDEBUG database, stored as runs `t03-llvm-case2`, `-case10`, `-case27`:
  - Case 10 (`APSInt.h:78`, report 137, `t03-llvm-case10-*`): the two `DestTy->isRealFloatingType()` results, each tagged "another `DestTy->isRealFloatingType()` result", answer the triager's question (the analyzer does not connect the calls at lines 3894 and 3904).
  - Case 2 (`WhitespaceManager.h:343`, report 131, step 7, `t03-llvm-case2-*`): `Next` reads "result of `begin()`, line 1356" with the tag, so the origin question is answered; whether it relates cell counts to cells is not.
  - Case 27 (`CheckExprLifetime.cpp:1450`, report 134, `t03-llvm-case27-*`): `LK` is 7 and reads "value from `std::memcpy(&R, this->Data, sizeof (R))` & 7". Partly: it says it is a masked value read out of a `PointerIntPair`, not that it is `getEntityLifetime()`'s result.

### Slice measurement (LLVM + Clang `lib/` and `tools/`, 3546 TUs, NDEBUG database of the first run, `-j8`, emission on, CodeChecker-written plists)

| Measure | After slice 1 | Before |
|---|---|---|
| Plists | 3545, 627,216,851 bytes | 560,384,519 (`cfg2/reports-all-on`) |
| Largest plist | 26,800,385 (`CompilerInvocation.cpp`) | 20,119,376 |
| Wall | 6478 s | 20,442 s (cfg2, load average up to 64); 3036 s (first run, load 15-25) |
| User | 23,339 s | 31,013 s (cfg2); 22,958 s (first run), so +1.7% |
| Max RSS | 4.03 GB | 4.13 GB (cfg2) |

- The plist growth of 66.8 MB (+11.9%) is the symbol table of tickets 01 to 03, which the pre-slice run did not have; XML integers cost several times their JSON bytes.
- Wall time is not comparable: this run shared the machine with lit, functest, browser and build runs, and averaged 3.6 busy cores against 7.5 in the first run. User time is the figure to trust.
- Over the 3255 traces, the table is 14.5 MB of JSON plus 5.5 MB of strings only it names, 20.1 MB of 231 MB trace bytes including CFG bodies (8.7%), or 25.7% of the trace without CFG bodies (78.1 MB with strings).
- 103,848 entries: region_value 28,783, conjured 51,280, derived 19,027, extent 4,734, metadata 24; all have a type, 50,202 are pointers.
- Conjured reasons: call_result 33,956, invalidation 14,279, other 3,045 (5.9%); loop_widening is 0 since the run does not widen loops.
- Top sources of `other`: `dynCastTo` 704, `memcmp` 569, `memcpy` 353, the atomic `fetch_sub` of `RefCount` 218, `simplify_type<...>::getSimplifiedValue` 167 (then `reinterpret_cast` of pointer bits 243 over two shapes). All are checker or builtin modelled; `memcmp` and `memcpy` come from `unix.cstring`.
  Scripts and numbers: `/Users/efulop/colorful-day-env/slice1/` (`measure.py`, `result.json`).

### Open points

- A compound's range stays raw (`[-2147483648, -1] [1, 2147483647]`) since the expression has no type; Clang could write the type of an expression too.
- Regions such as `Element{SymRegion{...},0 S64b,...}.Kind` and extents stay raw dumps; ticket 04 should widen `describeRegion`.
- `displayedStep` names a control step by the line choice it maps to, so a tag may link to "Arrow after step N".
- The first browser session on a rebuilt `www` needs a cache-busting query.
