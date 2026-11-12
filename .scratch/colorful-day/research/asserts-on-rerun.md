# LLVM scale run again with assertions visible to the analyzer

Date of every claim: 2026-11-12.

## Versions

- llvm-project HEAD at writing: `094e7a488fa7`. The working tree has uncommitted edits to analyzer headers (`PathDiagnostic.h`, `ExprEngine.h`, `SymbolManager.h`).
- Clang used for the new run: `build-colorful/bin/clang-24`, built 2026-11-12 14:43:54, `--version` reports `51cfbad5b480`.
- codechecker HEAD: `66253b294`. The package is the same `cfg2/pkg` the first run used.
- Analyzed source revision: the LLVM and Clang sources under `llvm/` and `clang/{lib,tools,include}` outside `clang/lib/StaticAnalyzer` are byte-identical between `a2b47aba60aa`, `6fbdf0613af7` and HEAD (`git diff` empty). Only `clang/lib/StaticAnalyzer/Core/PlistDiagnostics.cpp` differs between `6fbdf0613af7` and HEAD.
- Old run: `/Users/efulop/colorful-day-env/cfg2/reports-all-on` (assertions off), analyzed by the Clang of `llvm-project@a2b47aba60aa..5370369696d0`.
- New run: `/Users/efulop/colorful-day-env/asserts-on/reports`.

## What was done

- New configure dir `asserts-on/build`: Release, `LLVM_ENABLE_ASSERTIONS=ON`, `LLVM_ENABLE_PROJECTS=clang`, `CLANG_ENABLE_CIR=OFF`, `AArch64;X86`, `CMAKE_DISABLE_PRECOMPILE_HEADERS=ON`, same tablegen targets as `llvm-scale/logs/gen-final.txt`. The old configure dir and reports were not touched.
- `asserts-on/cdb-all.json` has the same 3546 entries in the same order and with the same compiler rewrite as `llvm-scale/cdb-all.json`.
- Where a file appears twice in the build database (`SummaryView.cpp`, `DummyClangFuzzer.cpp`), the entry with the old output path was used. One of the two `SummaryView.cpp` entries still differs from the old one in its target flags.
- Assertions are on in every TU. The compile line still contains `-DNDEBUG` from `CMAKE_CXX_FLAGS_RELEASE`, but CMake appends `-UNDEBUG` after it, so the preprocessor sees no `NDEBUG` (checked with `-E -dM` on 3 TUs).
- `LLVM_ENABLE_ASSERTIONS=ON` also adds `-D_DEBUG`, `-D_GLIBCXX_ASSERTIONS` and `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE` to all 3546 TUs. On `ASTReaderStmt.cpp` dropping the last two changed the analysis time from 140 s to 139 s, so they do not change cost. Their effect on reports was not measured.
- Analysis: `CodeChecker analyze --analyzers clangsa -j8 --analyzer-config clangsa:emit-constraint-snapshots=true`, same checkers (default set) as the first run. Nothing was stored; the server on port 8002 was not touched.
- Measurement scripts copied to `asserts-on/scripts/` (`measure.py`, `aggregate.py`, `last_step.py`, `assert_scan.py`, unchanged). `compare.py` and `ctrl.py` are new. The scripts reproduce the study on the old reports (639 of 1225 over an `assert(`, 395 / 562 / 487 in the last-step table).

## Failed TUs

- New run: 3544 commands analyzed, 0 failed, 3544 plists. CodeChecker de-duplicated the 2 duplicate-file entries; the old run also has 3545 plists for 3546 entries.
- Old run: 0 failures.
- TUs excluded from the comparison: 0. The 3544 source files are the same set in both runs.
- Wall time was 6192 s and user time 23,936 s at -j8. Wall time is not comparable to the first run: the machine was loaded by other workers (load 10 to 33) and one stretch of about 40 minutes made almost no progress (550 of 3544 TUs done at 14:58, 801 at 15:40), probably a machine stall. The old `cfg2` run had 20,442 s wall and 31,013 s user under similar load.

## Control for Clang drift

The new run uses a newer Clang than the first. To separate Clang drift from assertions, two control runs used the new Clang with the OLD compile database (`-DNDEBUG`, no assertions):

- `reports-ctrl400-ndebug`: the first 400 entries of the shuffled old database (400 TUs, 0 failed).
- `reports-ctrl30-ndebug`: the 27 TUs that hold the 30 triaged cases (27 analyzed, 0 failed).

The Clang binary's mtime (1794491034, 2026-11-12 14:43:54) is earlier than the start of every run in this document, so no run saw a changed binary.

Traced unique reports on the 400 control TUs:

| comparison | gone | new |
| --- | --- | --- |
| old run vs control (NDEBUG, new Clang) | 0 | 30 |
| control vs assertions on | 90 | 22 |
| old run vs assertions on | 63 | 25 |

Clang drift between the two builds only adds reports (179 old, 209 control). It removes none. All of the disappearances below are therefore caused by assertions, not by Clang drift. The "new-only" counts in the next section include drift: on the 400 TUs 30 of the new reports of an NDEBUG run already appear without any assertion.

## Report counts by unique report (hash, file, checker)

Old = first run, new = assertions on. All 3544 common TUs. Disappeared = in old, not in new. New-only = in new, not in old.

All reports: old 1474, new 1178, kept 939, disappeared 535, new-only 239.
Traced reports: old 1225, new 1053, kept 826, disappeared 399, new-only 227.

| checker | old | new | disappeared | new-only |
| --- | --- | --- | --- | --- |
| core.CallAndMessage | 497 | 304 | 239 | 46 |
| optin.cplusplus.UninitializedObject | 247 | 289 | 4 | 46 |
| deadcode.DeadStores (untraced) | 245 | 121 | 136 | 12 |
| security.ArrayBound | 86 | 76 | 17 | 7 |
| NewDelete / NewDeleteLeaks / Move | 64 | 51 | 21 | 8 |
| optin.cplusplus.VirtualCall | 57 | 57 | 2 | 2 |
| uninit family | 56 | 45 | 24 | 13 |
| core.NullDereference | 44 | 25 | 21 | 2 |
| core.NonNullParamChecker | 44 | 32 | 17 | 5 |
| core.DivideZero | 37 | 104 | 22 | 89 |
| core.BitwiseShift | 32 | 13 | 23 | 4 |
| core.StackAddressEscape | 29 | 30 | 2 | 3 |
| unix.* | 13 | 14 | 1 | 2 |
| core.NullPointerArithm | 10 | 8 | 2 | 0 |

Smaller checkers are in `asserts-on/compare.txt`.
Diagnostics in total fell from 7332 to 3737, and from 4077 untraced to 559.
DeadStores drops because a value that only an `assert` read is no longer dead.

## New DivideZero reports

DivideZero is the one big riser: 37 to 104 reports, 89 of them new.
89 of the 90 new-only DivideZero reports have an `assert(` line on their Bug Path.
Two mechanisms show up in the examples below; the split between them was not counted.

1. The assert condition contains a division, and the division is only compiled in when assertions are on.
   - `llvm/lib/Target/X86/X86ISelLowering.cpp:4528`: `assert(Vec.getValueSizeInBits() <= WideSizeInBits && ...)` reports "Division by zero" inside the assert expression itself.
   - `llvm/lib/Target/X86/X86ISelLowering.cpp:9404`: `assert((VT.getSizeInBits() == ShuffleVT.getSizeInBits()) && ...)`, same pattern.
2. An assert with a disjunction opens a zero branch.
   - `llvm/lib/Target/X86/X86ISelLowering.cpp:4478` (`vectorWidth / VT.getScalarSizeInBits()`): the path enters `TypeSize.h:201` `getFixedValue()`, whose `assert((!isScalable() || isZero()) && ...)` makes the analyzer assume the condition is false, then `getKnownMinValue` "Returning zero" and the division follows. In the release run that assert does not exist and the zero value never reaches the divisor.
   - The same pattern gives 15023, 15025, 15041 and 15110 in `AArch64ISelLowering.cpp`.

So assertions also add false positive candidates, not only remove them.

## The 30 triaged cases

Numbers are the case numbers in `triage-study/sample.tsv`; verdicts are those of `triage-study.md`.

- All 30 cases are present in the control (NDEBUG, new Clang) analysis of their TUs.
- With assertions on, 19 survive and 11 disappear.
- Disappeared: 3, 7, 10, 13, 14, 15, 18, 19, 25, 27, 28.
- Survived: 1, 2, 4, 5, 6, 8, 9, 11, 12, 16, 17, 20, 21, 22, 23, 24, 26, 29, 30. Their path length mostly stays within a few pieces (for example case 22 goes from 86 to 66, case 26 from 60 to 51).
- The 6 cases the study says turned on an assert (3, 7, 14, 15, 25, 28): all 6 disappear.
- The 23 false positives: 10 disappear (3, 7, 10, 13, 14, 15, 18, 19, 25, 27) and 13 survive (1, 2, 4, 5, 6, 8, 11, 12, 16, 17, 20, 22, 29). Cases 2 and 22 are the "likely" ones.
- Case 28 (cannot tell) disappears. Case 26 (cannot tell, leaning false positive) survives.
- All 5 true positives survive: 9, 21, 23, 24, 30.

The five disappearing false positives that the study did not attribute to an assert (10, 13, 18, 19, 27):
the control shows all five present when the same TUs are analyzed with the new Clang and `-DNDEBUG`, so Clang drift does not explain them.
They disappear only when assertions are on.
I did not read the new analysis of these five to find which assert (or library hardening check) removes each path, so the cause is established only as "assertions or the extra flags", not as a specific assert.
The study's own note for these cases did not blame an assert, so they show that an assert elsewhere in the callee or in a header can also decide a case that was triaged as a pure analyzer limit.

Sample-based reading: 10 of 23 false positives gone is 43%, from 23 cases, so it is a rough indication only.
Across the whole run, 399 of 1225 traced reports (33%) disappear, but 227 new traced reports appear (some from Clang drift, and 89 DivideZero from the mechanisms above).

## Tables A1 to A6 on the new reports

All tables are in `asserts-on/tables-new.md` (new) and `asserts-on/tables-old.md` (old, same script).
The population is 1053 traced unique reports instead of 1225.
Shifts of more than a few points, all reports (old to new):

| measure | old | new |
| --- | --- | --- |
| Bug Path passes over an `assert(` line (A6) | 639 of 1225 (52%) | 468 of 1053 (44%) |
| no variables at the last step (A1) | 395 (32%) | 393 (37%) |
| at least 1 symbol variable with SMT term at the last step (A1) | 562 (46%) | 478 (45%) |
| ... whose symbol is on the path condition (A1) | 487 (40%) | 416 (40%) |
| at least 1 symbol variable with SMT term at any step (A1) | 1119 (91%) | 956 (91%) |
| `derived_$` share of final path condition entries (A3) | 18% | 14% |
| `conj_$` share of final path condition entries (A3) | 37% | 39% |
| final path condition entries, median / p90 / max (A2) | 14 / 51 / 1430 | 18 / 66 / 770 |
| path condition changes in the bug's own frame (A5) | 19% | 26% |
| reports whose bug is not in the top frame (A5) | 927 (76%) | 782 (74%) |
| path condition changes at an "Assuming" event (A6) | 38% | 43% |
| ... at another event (A6) | 33% | 26% |
| "Assuming" events with no path condition change (A6) | 812 of 6425 (13%) | 530 of 5769 (9%) |
| final range is a single value other than 0 (A6) | 8% | 14% |
| final range is "other" (A6) | 17% | 13% |
| entries named by the panel (A4) | 9% | 8% |
| What-If addressable (A4) | 11% | 10% |

Everything else (A1 coverage, A4 naming, symbol kinds other than derived) moves by 3 points or less.
The assertion scan of the new run counts asserts the analyzer did see, so the 44% is not "asserts the analyzer missed"; it measures how many paths still cross an assert line, and it no longer implies that those asserts were invisible.

## Limits

- One 400-TU control and one 27-TU control, not a full NDEBUG rerun with the new Clang. The per-checker "new-only" numbers include Clang drift; the "disappeared" numbers do not (the control shows no disappearance from drift on the 400 TUs).
- The extra `-D_DEBUG`, `-D_GLIBCXX_ASSERTIONS` and libc++ hardening flags came with `LLVM_ENABLE_ASSERTIONS=ON` and were kept; their effect on reports was not separated from the LLVM `assert` effect.
- The key (hash, file, checker) can change if assertions change the context lines of a report; all 11 vanished cases were also checked for a report on the same file, line and checker only through `compare.py`, which found no such renamed report.
- The triage verdicts are the study's single-person verdicts on the old reports. I did not retriage the surviving cases on the new paths, so a surviving case may no longer be a false positive.
- The assert scan and the symbol classifications are the approximations of the original study.
- The wall time of the run is not a performance measurement (see above).
- A comparison of three kinds of data (old run, control, assertions on) exists only for the 400 TUs and the 27 case TUs.

## Files

- `/Users/efulop/colorful-day-env/asserts-on/`: `build/`, `cdb-all.json`, `reports/`, `reports-ctrl400-ndebug/`, `reports-ctrl30-ndebug/`, `new.jsonl`, `ctrl400.jsonl`, `ctrl30.jsonl`, `tables-new.md`, `tables-old.md`, `last_step-*.txt`, `assert_scan-*.txt`, `compare.txt`, `scripts/diff.json`, `logs/`.

## Cause of the 30 extra control reports (2026-11-12)

The 30 extra reports are a bookkeeping artifact of the comparison, not Clang drift and not Z3 timing.
The first run's unique reports were keyed by (hash, file, checker) and each key was assigned to the first TU it was seen in, out of 3546 TUs.
A report in a shared header is emitted by many TUs, so for these 30 the first-seen TU lay outside the 400-TU control sample.
The filter "first-seen TU is in the 400" therefore dropped them from the first run's count (179) but not from the control's (209).
All 30 are present, traced, in the first run's plists for TUs inside the 400.
Counting a key for every TU that holds it gives 209 for the first run and 209 for the control, with 0 lost and 0 new.
Affected checkers: security.ArrayBound (17), optin.cplusplus.UninitializedObject (9), core.BitwiseShift (2), cplusplus.NewDeleteLeaks (2).

Ruled out:
- Analyzer invocation: both runs used CodeChecker 6.30, the same checker list, `-j8`, `emit-constraint-snapshots=true`, and byte-identical compile commands for the 400 TUs; refutation is on in both (`crosscheck-with-z3=true`).
- Clang: no change under clang/lib, clang/include or llvm/lib between the two binaries that affects the analyzer. Running the 15 TUs that hold the 30 reports with the saved first-run binary (cfg2/old-clang) gives the same 61 traced reports as the current binary, so the symbol table in traces does not change which reports exist.
- Z3 timing: at the defaults `crosscheck-with-z3-timeout-threshold` is 15000 ms per query, `-rlimit-threshold` is 0 (unlimited), `-eqclass-timeout-threshold` is 0 (none) and `-max-attempts-per-query` is 3.
  A wall-clock timeout exists but is far above the query times seen here.
  Same 15 TUs: quiet -j1 twice (identical), -j8 under 16 busy loops (load average 37, identical), saved first-run binary (identical).
  No option change is needed for reproducibility on this sample.

Files are under /Users/efulop/colorful-day-env/asserts-on/drift-check/ (rep-a1, rep-a2, rep-b, rep-old, keys.py, extra30.json).
Fix for compare.py and ctrl.py: key each report by the set of TUs that emit it, or restrict both runs to the sampled TUs before deduplicating.
