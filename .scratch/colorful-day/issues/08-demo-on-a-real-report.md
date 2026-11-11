# 08: Demo on a real report

**What to build:** A repeatable demo that opens with the hand-written two-path example, then challenges one clear report from FFmpeg, tmux or Vim.
If none of those gives a clear example, propose another project.
This ticket also does the final visual pass on the debug view and judges the solver mismatch concern recorded in the spec.

**Blocked by:** 04, 06, 07

**Status:** ready-for-agent

- [x] One script or written procedure reproduces the demo data from a clean server.
- [x] The real report shows a What-If Constraint that gives a useful Infeasible verdict.
- [x] The two-path example shows the difference between this path and this bug.
- [x] Emission on the chosen real project completes, and the added report size is recorded.
- [x] The panel, toggle, picker and verdict are reviewed in a real browser at normal and narrow widths, and visual defects are fixed.
- [x] The spec's solver mismatch note is updated with what the demo showed.

## Comments

### Demo procedure

- `dev-loop.sh demo` rebuilds the demo from a clean server: it stops the running server, wipes `$CD_ENV/demo-workspace` (its own workspace, so the dev workspace of tickets 01 to 07 survives), starts the server on it, stores `demo/two-path-short.c` as `colorful-day-two-path` and all of tmux as `colorful-day-tmux`, and prints the two report URLs (report IDs 1 and 5 on a clean server). About 50 s with tmux already built.
- The script of what to click and say is `demo/README.md`.
- Ran it from clean seven times on 2026-11-10 and 11, the last after the picker check below.

### Real project: tmux 3.5a

- Tried in the order of fastest compile database. tmux was first because Homebrew already had `libevent`, `ncurses`, `autoconf`, `automake` and `bear`: clone, `autogen.sh`, `./configure --disable-utf8proc` (configure on macOS refuses to guess), `bear -- make -j10` took about 2 s, 146 compile commands.
- It gave a clear report on the first analysis, so Vim and FFmpeg were not tried. FFmpeg's configure and build are much larger, and nothing suggested Vim would do better.
- Chosen: `core.NullDereference` at `grid.c:1073` in `grid_string_cells`, 8 steps. Step 1 assumes `lastgc` is null (line 1051), Step 7 takes `flags & GRID_STRING_WITH_SEQUENCES` (line 1072), Step 8 dereferences `*lastgc`. The only callers are `grid-view.c:234`, which passes `NULL` with flags 0, and `cmd-capture-pane.c:184`, which passes `&gc`. So the What-If Constraint `flags == 0` at Step 1 states what the reader knows from the callers, and the verdict is Infeasible, dying at Step 7, the line that tests the flag. It also shows a first dead step later than the anchor.
- Rejected tmux candidates: `input.c:911` and `spawn.c:181` hinge on struct fields (`ictx->state`, `sc->flags`), which the grammar cannot name. `cmd-pipe-pane.c:144/153/156` (`open` fails, then `dup2(-1)`) and `reallocarray.c:39` (`nmemb` 0) are real edge cases, so an Infeasible verdict there would mislead. `window-copy.c:3264` (`buf` null after `window_copy_stringify`) works with `buf != null` but needs the reader to trust that tmux's allocator wrappers never return null, which is a weaker story.

### Added report size and time (tmux, whole project, `-j10`, Z3 refutation on, Apple Silicon)

| | emission off | emission on |
| --- | --- | --- |
| total plist bytes, 146 plists | 1,481,363 | 17,174,536 |
| analysis length, three runs (s) | 26.44, 26.25, 26.31 | 27.78, 26.56, 26.68 |

- Size grows 11.6 times, about 15.7 MB more for 30 path-sensitive reports, so about 520 KB per report. The bulk is the per-step `path_condition`, `symbol_ranges`, `variables` and SMT-LIB, repeated in full on every step. Deduplicating across steps would be the first thing to do if this went further.
- Time grows about 0.4 s on 26.3 s (medians), about 1.4%, within noise of one run.

### Visual pass

Open items from `wiki/web-ui-decisions.md`, all fixed in `codechecker@e78323748`:

- Cut-short search: the server now says whether the named step is proven earliest (`firstDeadStepIsEarliest`, API 6.79; false when the budget ran out or a probe came back unknown). The verdict then reads "It is dead by Step N. The solver gave up before it could tell whether an earlier step is dead too.", and the panel mark reads "Path dead here". Checked in the browser by setting `WHAT_IF_SEARCH_BUDGET_MS = 0` on the running server, then reverting it (`08-cut-short-{1400,900}.png`).
- Pointer ranges: `null` and `non-null` for `reg_`/`conj_` pointer symbols, raw range in the tooltip. Limit: a `derived_` pointer (as in `opaque-call.c` after `refresh()`) carries no type in its dump, so it keeps its interval. Integer ranges such as `[-2147483648, -1] [1, 2147483647]` were left as they are: the symbol's width is not in the dump, so a shorthand like `!= 0` could be wrong for another width.
- 900px `(`: it was the app bar title ("CodeChecker 6.30 Default") squeezed to 6px, not the file header branch label. Below 1280px the menu buttons are icons with tooltips. At 1400 the title had also been cut to "CodeChecker 6.30 ..." because it shared free space with the spacer; it now takes its own width.
- Path and "Found in:" gap: 12px column gap in the header. At 900 the path had shrunk to its copy icon (34px) on tmux; with a 16rem minimum, "Found in:" wraps to its own line instead.

Other defects found on the real report and fixed:

- Clicking the dead step in the verdict scrolled its line only to the bottom edge, with the bubble below it out of view; it now scrolls to the center.
- A field's symbol dump under a variable ran to seven lines on tmux (`end`); it is clamped to two lines with the full dump in its tooltip.
- At 900 the page was scrollable by 26 to 29px: `FillHeightDirective` measured the viewport top, so a scrolled page made the editor taller by the scroll offset, which kept the page scrollable. It now measures the document top and also re-measures when the body resizes (the header wraps after the "Found in" selector loads).

Screens in `/Users/efulop/colorful-day-env/screens/`, all at 1400 and 900: `08-two-path-a-eq-0-*` (Infeasible at Step 1), `08-two-path-b-eq-0-*`, `08-tmux-off-*` (toggle off), `08-tmux-flags-eq-0-*`, `08-tmux-dead-step-*` (after clicking Step 7), `08-tmux-line-1065-*`, `08-cut-short-*`.
No tmux line in this Bug Path holds two steps with different snapshots (line 1065's two events share one, so ticket 04's rule selects Step 4 directly), so the picker was checked on `demo/loop.c` line 7, stored briefly on the demo server before a final clean `dev-loop.sh demo`: `08-picker-{1400,900}.png`, three rows told apart by `i`.

### Traps

- Sourcing the venv's `activate` a second time restores the PATH saved at the first activation, which drops the Colorful Day Clang. In `dev-loop.sh demo` the tmux analysis ran after `cmd_store` and failed with "clangsa has no config named 'emit-constraint-snapshots'". `cmd_demo` calls `use_clang` again.
- The vue-cli build prepends Vuetify's styles to every `lang="scss"` block, so a `<style lang="scss" scoped>` re-emits Vuetify's reset as `[data-v-...]{padding:0}` and strips the padding off that component's buttons. `TheHeader.vue` uses a plain `<style scoped>`.
- The editor's vertical scroller is `.v-row.editor`, not `.cm-scroller`. A DOM `scrollIntoView` on a `.cm-line` in a browser check scrolls `.cm-scroller` sideways and fakes a horizontal shift that a real click does not cause.
- `report_id` in `dev-loop.sh` finds reports by file and line, so editing `demo/two-path-short.c` means updating the line there (10 now).

### Solver mismatch

All 30 tmux Bug Paths have a Feasible Baseline Verdict under Z3 (slowest 10 ms), and both demo checks die where a forward run with the same assumption would also have stopped. The dated note is in the spec's Further Notes.

### Test results (2026-11-11)

- `dev-loop.sh lit`: 4 passed, 1 unsupported (no-z3). Clang was not touched, so `clang/test/Analysis` was not run.
- `dev-loop.sh functest`: 28 passed, now also checking `firstDeadStepIsEarliest` through the API.
- Server unit: 98 passed (`test_ccldap.py` excluded, no `ldap`), with new assertions in `test_what_if.py` for the earliest flag after a full search, a spent budget and a solver that gives up.
- `store` 7/7. `report_viewer_api` 66/67, the known Clang 14 expectation in `test_get_run_results_checker_id_and_file_path`.
- Report-converter unit: 136 passed. No tracked files changed by the runs in either repository.
- `eslint` on the five touched UI files, `pycodestyle`, and `pylint` 10.00 on `what_if.py` and its unit test: clean. `shellcheck dev-loop.sh`: clean.
