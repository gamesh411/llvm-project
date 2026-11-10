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
