# Execution plan

Related: [worker rules](worker-rules.md), [dev environment](dev-environment.md).
Sources: `../spec.md`, `../issues/`.

## 2026-11-10: initial plan

On 2026-11-10 the user asked for the tickets created in `llvm-project@d417c2ac2026` to be implemented.

Order, from each ticket's `Blocked by` line:

1. 01 dev loop.
2. 02 tracer bullet through both repositories.
3. 03 and 04, both blocked only by 02.
4. 05, blocked by 03.
5. 06 and 07, both blocked by 05.
6. 08 demo, blocked by 04, 06 and 07.
7. 09 and 10 are stretch goals, and ticket text makes them conditional on 08 working and on time remaining.

On 2026-11-10 the lead decided to run tickets one at a time unless a pair is shown to touch disjoint files.
03 and 04, and 06 and 07, all edit the same Clang piece construction, plist output and web panel code, and both repositories have a single `colorful-day` branch.

On 2026-11-10 the lead decided to check with the user before starting 09 and 10, because the tickets condition them on time remaining and only the user knows that.

## 2026-11-10: open point for ticket 08

As of `llvm-project@da4604b880b8`, `../demo/two-path.c` resets and reassigns `p` to force the spec's Bug Path `a == 0`, `b != 0`.
The ticket 01 worker reported that the simpler `p = &x; if (a == 0) p = 0; if (b != 0) p = 0;` is reported along `a != 0`, `b != 0`, where `b == 0` also rules out this path while the bug remains through `a`.
Ticket 08 should decide which version explains "this path" against "this bug" best in a one-minute demo.
This open point is settled by the 2026-11-11 two-path entry below.

## 2026-11-10: progress

On 2026-11-10 the lead accepted ticket 03 after viewing `/Users/efulop/colorful-day-env/screens/03-panel-1400-step2.png` and `03-panel-1400-last-step.png`, and started ticket 04.

On 2026-11-10 the lead accepted ticket 04 after viewing `04-picker-1400.png` and `04-offpath-hint-1400.png`, and started ticket 05.

On 2026-11-10 the lead accepted ticket 05 and started ticket 06, with 07 to follow once 06 is in, since both extend `what_if.py` and the panel.

On 2026-11-10 the lead accepted ticket 06 after viewing `06-multi-unknown-1400.png` and `06-syntax-error-1400.png`, and started ticket 07.

On 2026-11-10 the lead accepted ticket 07 after viewing `07-dies-before-anchor-1400.png` and `07-toggle-on-infeasible-1400.png`, and started ticket 08.

## 2026-11-11: two-path example settled by ticket 08

On 2026-11-11 the ticket 08 worker chose the simpler version for the demo, as `../demo/two-path-short.c`, and kept `../demo/two-path.c` as the fixture source so the functional tests need no new fixture.
The simpler version is reported along `a != 0`, `b != 0` (checked with the Colorful Day Clang at `llvm-project@8c98b9a644c8`), so the `a == 0` route to the same bug is visible in the source but not on the Bug Path.
Checking `a == 0` then makes this path Infeasible while that same assumption is exactly the other route to the bug, which explains "this path" against "this bug" in one step.
The forced version needs two extra resets that a viewer has to read first, and its `b == 0` story needs the viewer to trace four branches.

## 2026-11-11: ticket 08 accepted, stretch goals pending

On 2026-11-11 the lead accepted ticket 08 after viewing `/Users/efulop/colorful-day-env/screens/08-tmux-flags-eq-0-1400.png` and `08-two-path-a-eq-0-900.png`, at `llvm-project@41963c03f695` and `codechecker@e78323748`.
The demo uses tmux 3.5a, `grid.c:1073`, with `flags == 0` at Step 1 dying at Step 7. The rejected candidates are in the Comments of `../issues/08-demo-on-a-real-report.md`.
The ticket 08 worker measured plist output on the whole of tmux growing 11.6 times (about 520 KB per path-sensitive report), with analysis time up about 1.4%.
Small wording issue left: when the dead step equals the anchor, the verdict repeats the step ("at Step 1. It dies at Step 1").
The wording issue is superseded by the cleanup entry below, which records its fix in `codechecker@4be03b7d7`.
Tickets 09 and 10 wait for the user's go-ahead, per the 2026-11-10 decision above.
The wait is superseded by the user's approval in the next paragraph.

On 2026-11-11 the user approved the stretch tickets. The lead started 09, with 10 to follow once 09 is accepted, since 10 is blocked by 09.

On 2026-11-11 the lead accepted ticket 09 and started ticket 10.

On 2026-11-11 the lead accepted ticket 10 after viewing `/Users/efulop/colorful-day-env/screens/10-contexts-states-1400.png`, and started a cleanup pass. The pass covers the trim-path gap, the outdated option description, an unexplained `functest` setup failure ("Failed to add the product to the test server!"), a final `clang/test/Analysis` run on the final Clang, and setting ticket `Status` lines to `resolved`, the term the tracker's wayfinding section uses.

## 2026-11-11: cleanup pass done

On 2026-11-11 the lead accepted the cleanup pass.
The verdict no longer repeats the step when the path dies at the anchor, as of `codechecker@4be03b7d7`.
Trace paths are trimmed and a failed `functest` setup cleans up after itself, as of `codechecker@333e8467d`.
The option description and ticket `Status` lines were updated in `llvm-project@2872a9cbe8f3`.
The store zip race behind the `functest` setup failure was fixed in `codechecker@63ec865ce`, as recorded in [dev environment](dev-environment.md).

## 2026-11-11: scaling pass

On 2026-11-11 the user asked for the Clang build to be relinked against z3 5.4.0, and for the mitigations in `../perf-evaluation.md` to be applied so that a project as big as LLVM itself can be viewed, each mitigation in its own commit and NFC where possible.

On 2026-11-11 the lead split the work into two lanes that touch different repositories, so they run in parallel:

- Lane A, llvm-project: relink `build-colorful`, then mitigation 1 (lazy, cached snapshots and assertion printing), which must leave the plist output unchanged apart from the analyzer's own non-determinism.
- Lane B, codechecker: mitigation 3 (fetch details once), mitigation 4 (`shallowRef` and precomputed snapshot keys), mitigation 5 (per-worker What-If cache), all NFC, then mitigation 14's explicit thrift string limit, which is a fix with a test.

After both lanes, one worker at a time, since each spans both repositories:

1. Trace format v2, combining mitigations 2, 6 and 10's shared declarations: a snapshot table per report, per-step deltas, interned strings and SMT declarations once per report. This one is not NFC, because the format changes.
2. Mitigation 7: lazy trace fetching, only when "Show constraints" is on.
3. Mitigation 11's size guard as a safety net, and mitigation 8 (gzip) only if measurement after steps 1 and 2 still shows a need.

On 2026-11-11 the lead set the acceptance target: LLVM analyzed with emission on, stored, and a long-path report opened in the browser, with page ready time, store time and sizes measured against `../perf-evaluation.md`.

On 2026-11-11 the lead accepted lane A.
A plain ninja build relinked `build-colorful` against z3 5.4.0, because ninja tracks `/opt/homebrew/lib/libz3.dylib`, so no CMake reconfigure was needed.
As of `llvm-project@385184e2a529`, snapshots are built once per node, only for pieces left after pruning, and their text is printed once per report.
The worker showed NFC on 163 plists (tmux 3.5a, the bench TUs and `../demo/*.c`), which all match the old binary once the run-to-run noise in symbol and node IDs is normalized.
`cmd-find.c` went from 1.44-1.55 s to 0.99-1.04 s, about the same as with emission off.
Variables are still read eagerly, because `getSVal` creates symbols the first time it reads a parameter or global, and reading fewer of them renumbered later symbols.

On 2026-11-11 the lead accepted lane B after viewing `/Users/efulop/colorful-day-env/screens/scale-m14-r440-stored-1400.png` and `scale-m4-grid-cfg-1400.png`.
As of `codechecker@0afb4de34`, the page fetches report details once per open, and as of `codechecker@faebe8d23` the trace sits outside deep reactivity, so at 605 steps CFG open went from about 670 to about 100 ms and States open from about 630 to about 35 ms.
As of `codechecker@2d2fb1b74`, each API worker keeps prepared Bug Paths in an LRU of 8, keyed by a sha256 of the stored path data, because SQLite here reuses a deleted report's ID; a repeated 1205-step check takes 13-62 ms instead of about 0.9 s.
As of `codechecker@46a0137a3`, the thrift string limit is explicitly none on the server and Python clients, and `web/requirements.txt` requires `thrift~=0.25`, the first version with that argument.
UI problems seen and queued for a later polish worker: three-digit step numbers overflow their round badges, variables sort as a0, a1, a10, a100, and the report tree keeps its old selection after a line click.
`dev-loop.sh env` does not install `python-ldap`, which the server unit tests need.

On 2026-11-11 the lead decided that trace format v2 replaces v1 everywhere instead of both being read, so there is one reconstruction path in each consumer.
A stored v1 trace gets the disabled toggle with an explanation, as a report without constraint data does, and `dev-loop.sh demo` rebuilds the demo from a clean server.

## 2026-11-11: wiki lint corrections

The UI problems in the lane B entry above were seen as of `codechecker@46a0137a3`, and the missing `python-ldap` as of `llvm-project@385184e2a529`.

## 2026-11-11: trace format v2 accepted

On 2026-11-11 the lead accepted trace format v2 after viewing `/Users/efulop/colorful-day-env/screens/v2-r1205-cfg-1400.png`, `v2-tmux-flags-eq-0-1400.png` and `v2-stored-v1-disabled-1400.png`.
The commits are `llvm-project@2ea8cfaee13f..b431273aaad1` and `codechecker@701a97292..54e8c88b7`, and the schema is in `../trace-format-v2.md`.
The equivalence check found a v1 bug, fixed on its own in `llvm-project@2ea8cfaee13f`: the node table was keyed by the analyzer's node ID, which the exploded graph reuses after reclaiming nodes, so at 1205 steps 68 entries each stood for two nodes.
Apart from those node entries, all 3491 steps rebuilt from v2 by the Python, JS and lit readers match the v1 output of `llvm-project@385184e2a529`, and 1754 What-If checks give identical verdicts.
The worker's measurements, before and after:

| Measure | 605 steps | 1205 steps |
|---|---|---|
| plist size | 54.7 MB -> 1.18 MB | 215 MB -> 2.36 MB |
| store time | 14.3 s -> 6.6 s | 45.2 s -> 6.7 s |
| store client memory | 536 MB -> 57 MB | 1.98 GB -> 62 MB |
| getReportDetails | 27 MB in 0.86 s -> 314 KB in 0.02 s | 107 MB in 3.43 s -> 632 KB in 0.03 s |
| page ready | 3.1 s -> 0.88 s | 10.4 s -> 1.34 s |

Size now grows about 2.0 times per path doubling, against 3.9 before, and tmux plists went from 23.5 to 6.9 MB.
Step clicks stayed at about 180-350 ms, which the worker traced to rendering 400-800 panel rows, not to reading the trace.
As of `codechecker@44129629f`, edges into one graph block share a gutter lane, because at 1205 steps a 3200 px gutter pushed the graph out of view.

On 2026-11-11 the lead decided to defer mitigation 7 (lazy trace fetching) and mitigation 8 (gzip), because report details at 1205 steps are 632 KB fetched in 0.03 s, so neither has a measured need.
The LLVM run comes next instead, and its measurements decide whether 7, 8 or 11 is needed.
In parallel, a UI polish worker takes the queued problems, the slow step clicks, and the report tree not scrolling the source to a clicked step, which the v2 worker saw on the old build as well.

## 2026-11-12: LLVM run, acceptance target met

On 2026-11-12 the lead accepted the LLVM run after viewing `/Users/efulop/colorful-day-env/screens/llvm-r1031-1100steps-step.png` and `llvm-r927-90steps-states.png`, measured at `llvm-project@6fbdf0613af7` and `codechecker@54e8c88b7`, not at the polish head.
All 3546 TUs of `llvm/lib`, `llvm/tools`, `clang/lib` and `clang/tools` were analyzed with emission on in 50.6 minutes at `-j8`, stored in 660 s (404 s of it git blame), and opened in the browser.
The full table against `../perf-evaluation.md` is in `/Users/efulop/colorful-day-env/llvm-scale/results.md`.
Emission costs +2.6% wall time on a 150-TU slice, but plists are 1.44 GB, 17.2 times the off size, the largest 97 MB (`CompilerInvocation.cpp`).
CFGs are 87% of trace JSON and steps 0.8%, so CFGs repeated in every report of a TU now drive size, and a store peaks at 4.55 GB in the client and 5.1 GB in one server worker.
getReportDetails stays at or under 3.8 MB and 129 ms, so mitigations 7 and 8 stay deferred.
Slow step clicks and page ready times on long reports are the same with "Show constraints" off, so they are CodeChecker's own.
Opening the CFG on the 1100-step report takes 6.9 s, for one block of about 180 rows.
Visual defects found: multi-file tree labels show only the file name; States frame names clip without an ellipsis and stray chevrons sit on their own rows; symbol dumps wrap mid-identifier and carry absolute paths; report 927 offers no What-If variables while the placeholder says `x == 0`; a selected bubble hides under about 180 stacked "Entered call" bubbles; a CFG arrowhead overlaps its "F" label; the function picker truncates.
The LLVM setup traps (precompiled headers and CIR on by default, Apple libc++ paths) are in Open Brain.

On 2026-11-12 the lead decided the next worker shrinks CFGs (mitigation 12) and makes the CFG view fast on huge blocks, both in one worker because both change the CFG data and its reader, followed by a second polish worker for the visual defects above and the two left open by the first.
Mitigation 11's size guard waits for that measurement, since the CFG change targets the same driver.

## 2026-11-12: CFG and store pass accepted

On 2026-11-12 the lead accepted the CFG and store pass after viewing `/Users/efulop/colorful-day-env/screens/cfg2-r1313-30500rows-subexpr-1400.png` and `cfg2-r133-edge-labels-1400.png`.
The commits are `llvm-project@a2b47aba60aa..5370369696d0` and `codechecker@07f4fbcc9..e7da30fe6`.
As of `llvm-project@a2b47aba60aa`, each CFG body is kept once per plist file in a top-level `constraint_trace_cfgs`, and traces name it by index. As of `codechecker@398558744`, CodeChecker plists hold the blocks as JSON text.
The stored per-report trace is unchanged, so there is no version bump and no database change.
The worker rejected three alternatives: interning element texts (plist 1.27 times smaller), dropping CFGs no step uses (10% of the bytes), and sharing across TUs (6.6 against 6.2 times per file).
Profiling showed the old store peaks were the whole run held in the client, a whole-zip `read()`, and one combined plist parsed on the server. As of `codechecker@567bc3fdf..cba10dbb5`, the store writes per input file and streams, and the server unzips in pieces.
As of `codechecker@1623a33af`, the CFG view renders only blocks and rows in view, so a 30,500-row block with Subexpressions on opens in 65 ms instead of 2563 ms.
The 6.9 s CFG open in the LLVM run entry above was a measurement artifact: work left over from earlier step clicks landed in the timed click, and settled it took 45 ms.
On the whole LLVM set, plists went from 1,444 to 560 MB, the largest from 97.2 to 20.1 MB, the store client peak from 4.55 to 2.10 GB and one server worker from 5.11 to 1.89 GB.
3255 of 3255 traces with CFGs rebuild identically, and 1166 of 1166 What-If checks give the same verdicts.
Left open as of `codechecker@e7da30fe6`: both remaining peaks are Thrift's JSON codec moving the whole 112 MB base64 store zip, which is CodeChecker's own `massStoreRun` design. CFG rows scrolled out of view are not in the DOM, so Ctrl+F does not find them.
Mitigation 11's size guard has no remaining measured need, since the largest plist is 20.1 MB.
