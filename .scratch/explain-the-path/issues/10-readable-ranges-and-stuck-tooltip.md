# 10: Readable ranges and the tooltip that stays open

**What to build:** Ranges in the panel read the way a person would say them, and the "Show constraints" tooltip closes after a click.
This ticket is outside `../spec.md`: it is the direct ticket agreed on 2026-11-12, and on that day the user asked for it to be done first.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] An integer range that excludes exactly one value reads "not N", such as "not 0" for `[-2147483648, -1] [1, 2147483647]`.
- [x] A single-value range reads as the value, such as "1" for `[1, 1]`.
- [x] A range from a value to the type's maximum reads "at least N", and from the type's minimum to a value "at most N", when the type's bounds can be told from the symbol's type in its dump. A range whose type cannot be told is left as it is.
- [x] Any other range is shown as today.
- [x] The analyzer's own range is on hover wherever a readable form is shown, as it is for null and non-null.
- [ ] The readable form is used in the Constraint Snapshot, the accumulated path condition and the line picker.
- [x] A jest test covers each form for signed and unsigned types of several widths, and the fallback.
- [x] The "Show constraints" tooltip closes after the checkbox is clicked. The defect is reproduced in a browser before the fix.
- [ ] Verified in a browser at 1400 and 900 pixels on the two-path demo and the tmux demo report, with screenshots.
- [x] The CodeChecker documentation page's paragraph on how ranges are printed is updated.

## Comments

Done in codechecker on `colorful-day`, in separate commits: the formatter and its use, the tooltip, a fix for the comma, and the docs paragraph with a retaken `constraints_panel.png`.

- `readableRange(range, symbol)` is beside the other helpers in `ConstraintTrace.js`, tested first in jest.
  The analyzer prints a comma between intervals (`[a, b], [c, d]`), which the ticket text does not show, so the first version matched nothing in the browser and a second commit fixed it.
- Type bounds come from the type at the start of the dump (`reg_$1<int a>`, `conj_$2{unsigned long, ...}`).
  Told: int, short, long long, `__int128`, signed or unsigned char, each with const or volatile.
  Left alone: typedefs (`size_t`, `__size_t`), enums, plain `char`, pointers, floats, and expressions such as `(a) - (b)`.
- Decision: `long` is 32 or 64 bits by target, so it is read as 64-bit, which is certain only when a range reaches the 64-bit extreme; a long range that ends at 2147483647 is left alone.
- Decision: "not N" needs the type's bounds, so `[1, 5] [7, 9]` is never "not 6".
  It also covers an unsigned `[1, max]` ("not 0") and a signed range missing only the minimum or maximum.
  A range outside the type's bounds is left alone.
- The hover title keeps the analyzer's range in the snapshot and path condition.
  The line picker shows the readable form and the analyzer's ranges in the hover title of its values line.
- Tooltip: reproduced with chrome-devtools-axi (hover, click toggles the box, the hint stays open while the pointer rests).
  Fix: the tooltip is controlled and closes on the checkbox's `update:model-value`; leaving and re-entering opens it again.
- Verified in the browser: two-path demo at 1400 (panel shows "not 0", title has the range), tmux file.c:L394 at 900 and 1400 (accumulated path condition shows "not 0"), tmux report 9 shows "not 1" with title `{ [-2147483648, 0], [2, 2147483647] }`.
- Not done: the line picker could not be opened in the browser (synthetic clicks on a source line did not open it), so its readable form is covered by jest of the formatter and by reading the code only.
  The 900 pixel two-path view was not screenshotted; the 900 pixel tmux view was.
  Pointer differences such as `(a) - (b)` keep the analyzer's range, as they are compound expressions.
