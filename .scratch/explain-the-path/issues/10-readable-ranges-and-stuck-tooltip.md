# 10: Readable ranges and the tooltip that stays open

**What to build:** Ranges in the panel read the way a person would say them, and the "Show constraints" tooltip closes after a click.
This ticket is outside `../spec.md`: it is the direct ticket agreed on 2026-11-12, and on that day the user asked for it to be done first.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] An integer range that excludes exactly one value reads "not N", such as "not 0" for `[-2147483648, -1] [1, 2147483647]`.
- [ ] A single-value range reads as the value, such as "1" for `[1, 1]`.
- [ ] A range from a value to the type's maximum reads "at least N", and from the type's minimum to a value "at most N", when the type's bounds can be told from the symbol's type in its dump. A range whose type cannot be told is left as it is.
- [ ] Any other range is shown as today.
- [ ] The analyzer's own range is on hover wherever a readable form is shown, as it is for null and non-null.
- [ ] The readable form is used in the Constraint Snapshot, the accumulated path condition and the line picker.
- [ ] A jest test covers each form for signed and unsigned types of several widths, and the fallback.
- [ ] The "Show constraints" tooltip closes after the checkbox is clicked. The defect is reproduced in a browser before the fix.
- [ ] Verified in a browser at 1400 and 900 pixels on the two-path demo and the tmux demo report, with screenshots.
- [ ] The CodeChecker documentation page's paragraph on how ranges are printed is updated.
