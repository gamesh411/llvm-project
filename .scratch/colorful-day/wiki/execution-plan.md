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
