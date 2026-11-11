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
