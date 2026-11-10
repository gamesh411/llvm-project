# Web UI decisions

Related: [execution plan](execution-plan.md).
Source: `../issues/02-show-ranges-for-event-steps.md`.

## 2026-11-10: toggle and panel placement

As of `codechecker@45840c305`, the toggle was a 16px `(x)` icon with a tooltip, and the side panel took the full right column including the toolbar row.
The toolbar wrapped when the panel opened, leaving the icon alone on a second row, and `Comments` overflowed the row by about 1.8px.

On 2026-11-10 the lead rejected that layout, because user story 5 needs the toggle to be findable and the panel should not reflow the toolbar.
The lead decided that the toggle is a labelled checkbox matching "Show arrows", and that the panel sits below the toolbar, beside the source view only.

## 2026-11-10: rework accepted

As of `codechecker@3cdc9faee`, the toggle is a labelled "Show constraints" checkbox stacked under "Show arrows", and the panel sits beside the source view only.
This implements the decision above, which supersedes the 16px icon layout of `codechecker@45840c305`.
On 2026-11-10 the lead viewed `/Users/efulop/colorful-day-env/screens/02b-panel-1400.png` and `02b-off-1400.png` and accepted it.
A tight gap remains between the elided file path and "Found in:" in the file header, left for the ticket 08 visual pass.

## 2026-11-10: ticket 04 line selection

On 2026-11-10 the lead accepted two ticket 04 worker decisions, as of `codechecker@41f307f73`.
Steps on one line with identical snapshots count as one picker choice, the event if there is one, so an `if` line does not open a picker whose rows all show the same panel.
The worker also fixed a 2px per bubble drift between line numbers and source text, and let clicks pass through the arrow overlay while "Show constraints" is on.

In `/Users/efulop/colorful-day-env/screens/04-picker-1400.png` the lead saw the source area end at a dotted vertical line about two thirds across, with blank space to its right while the panel is closed. This was assigned to the ticket 05 worker to fix.

## 2026-11-10: ticket 05 What-If section

As of `codechecker@0010a3dec`, the dotted line from ticket 04 turned out to be CodeMirror's focus outline around an editor only as wide as its code, and the outline was removed. Making the editor full width was rejected because it made the step bubbles' right edges uneven.
On 2026-11-10 the lead viewed `/Users/efulop/colorful-day-env/screens/05-b-eq-0-infeasible-1400.png` and accepted ticket 05.
In that screenshot the What-If section cuts the accumulated path condition off mid-line with no sign that it scrolls, so the lead assigned that to the ticket 06 worker.
