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
That cut-off is superseded by the 2026-11-11 wiki lint entry below.

## 2026-11-10: open items for the ticket 08 visual pass

- A verdict from a search the solver cut short still says "the first step", which the server cannot prove in that case, as of `codechecker@6325f9164`.
- Pointer ranges read as `[1, 18446744073709551615]` in `/Users/efulop/colorful-day-env/screens/07-toggle-on-infeasible-1400.png` instead of something like non-null.
- At 900px the file header's branch label truncates to `(`.
- The tight gap between the file path and "Found in:" noted after ticket 02.

## 2026-11-11: ticket 08 visual pass

As of `codechecker@e78323748` the four open items above are resolved:

- A search the solver cut short now says "It is dead by Step N. The solver gave up before it could tell whether an earlier step is dead too.", and the panel mark reads "Path dead here". This needed `WhatIfResult.firstDeadStepIsEarliest` (API 6.79).
- A pointer symbol's `{ [0, 0] }` and `{ [1, 18446744073709551615] }` read `null` and `non-null`, with the range in the tooltip. Pointers are recognized from the type at the start of a `reg_` or `conj_` dump, so a `derived_` pointer still shows its interval.
- The 900px `(` was the app bar title clipped to its first letter, not the file header. Below 1280px the menu now shows icons with tooltips, and the title no longer shares free space with the spacer.
- The file header has a 12px gap between its parts, and below a 16rem path "Found in:" wraps to its own line, where before the path shrank to its copy icon.

Other defects fixed in the same pass are in the Comments of `../issues/08-demo-on-a-real-report.md`.

## 2026-11-11: ticket 09 graph view

As of `codechecker@b31cdd260`, the graph view is HTML block cards with SVG edges in a gutter, with no new npm dependency and the Content Security Policy unchanged. It floats over the right part of the source column, covering it entirely when the column is under 600px.
On 2026-11-11 the lead accepted that layout after viewing `/Users/efulop/colorful-day-env/screens/09-tmux-cfg-dead-step-1400.png` and `09-loop-cfg-picker-900.png`.

## 2026-11-11: wiki lint corrections

The What-If cut-off noted in the ticket 05 entry above is fixed as of `codechecker@da8c060ca`: the snapshot and the What-If section share the panel height, with at least 120px for the snapshot and at most 55% for What-If, and each scrolls with an edge shadow. The source is the Comments of `../issues/06-full-what-if-input-and-unknown.md`.

The pointer ranges, the 900px `(` and the file header gap in the open items list above were seen as of `codechecker@6325f9164`, the head when ticket 07 was accepted.

On 2026-11-11 the lead queued three UI problems, seen as of `codechecker@46a0137a3`, for a polish worker after trace format v2: three-digit step numbers overflow their round badges, variables sort as a0, a1, a10, a100, and the report tree keeps its old selection after a line click.
These are superseded by the polish pass entry below.

## 2026-11-11: polish pass accepted

On 2026-11-11 the lead accepted the polish pass after viewing `/Users/efulop/colorful-day-env/screens/polish-after-r1205-step251-1400.png` and `polish-after-r3005-step1001-1400.png`.
As of `codechecker@66910a255`, three-digit step numbers take 10px inside the 24px badge, and from four digits the badge becomes a pill.
As of `codechecker@0e8bbba35`, the panel's variables and the line picker's values use a natural sort.
As of `codechecker@1c7c3bd4c`, the report tree follows a step selected anywhere else, after the next paint, because activating a tree item re-renders every item (about 200 ms at 400 steps).
As of `codechecker@8693c4955`, panel rows use `content-visibility: auto`.
The worker found that the slow step clicks noted in the v2 entry of [execution plan](execution-plan.md) were not the panel's doing: a 1205-step tree click spends about 190 ms in Vuetify's tree and about 100 ms in jsPlumb arrows, 285 ms with constraints off too, and the panel took about 10 ms.
A first click on the already-active tree item only deactivates it, which is Vuetify's toggle and upstream behavior, left as is.
Left open as of `codechecker@8693c4955`: the accumulated path condition still lists symbols in symbol order (a98, a99, a100 ... a8), and at 900px the tree pane clips labels to "L23", as it did before.
