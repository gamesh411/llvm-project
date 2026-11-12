# 03: Labels everywhere, and unrelated values of the same call

**What to build:** Symbol labels appear wherever a symbol is shown, and a report reader can see when the analyzer treats two calls with the same text as returning unrelated values.
This ticket closes slice 1 of `../spec.md`.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] A compound symbolic expression renders from the labels of its atoms, such as "result of `size()` + 1", with the raw dump on hover.
- [ ] The line picker, the CFG view and the States view use labels where they show a symbol.
- [ ] Two symbols on the Bug Path whose origins are calls with the same statement text are each marked as a different value of the same call, with a link to the other's Path Step.
- [ ] Long statement text is shortened, with the full text on hover.
- [ ] Labels are never used as row keys, and two symbols with the same label stay two rows. A jest test covers this.
- [ ] Slice acceptance in a browser at 1400 and 900 pixels: the two-path demo, the tmux demo report, and three LLVM reports from the triage study, one of them a case where two unrelated symbols share call text (cases 2, 10 or 12).
- [ ] Plist size and analysis time on the LLVM run are reported against the 2026-11-12 figures in `../../colorful-day/wiki/execution-plan.md`.
- [ ] Both documentation pages describe the labels.
