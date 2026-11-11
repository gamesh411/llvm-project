# Colorful Day demo

A three-minute demo: first the hand-written two-path example, then one real report from tmux.

## Rebuild the demo data

```sh
.scratch/colorful-day/dev-loop.sh demo
```

It stops the running dev server and wipes `$CD_ENV/demo-workspace`.
It then starts the server on that clean workspace, on port 8002.
It analyzes and stores `two-path-short.c` as run `colorful-day-two-path`.
On first use it clones tmux 3.5a into `$CD_ENV/projects/tmux` and builds a compile database with `bear`.
It analyzes all of tmux with Z3 refutation and constraint emission, stores it as `colorful-day-tmux`.
It then stores `several-contexts.c` as `colorful-day-contexts`, and prints the three report URLs.
It takes about 50 seconds once tmux is built.
The dev workspace of earlier tickets is not touched.
Afterwards the server runs on the demo workspace, so `dev-loop.sh stop` and `server` bring back the dev one.

Needs a built `dev-loop.sh clang`, `env`, `web` and `package`, plus Homebrew `bear`, `libevent`, `ncurses`, `autoconf` and `automake`.

On a clean server the URLs are:

- two-path: `http://localhost:8002/Default/report-detail?report-id=1`
- tmux: `http://localhost:8002/Default/report-detail?report-id=5`
- several contexts: `http://localhost:8002/Default/report-detail?report-id=33`

Use a window at least 1280 pixels wide, so the menu keeps its labels and the panel leaves room for the code.

## Part 1: this path against this bug (one minute)

`two-path-short.c` is a different file from `two-path.c`, which stays the source of the functional test fixtures.
Ticket 08 explains why the demo uses the short one.

1. Open the two-path URL.
   Say: "One function, two ways for `p` to become null: `a == 0` on line 7, or `b != 0` on line 9. The analyzer reports the bug once, and shows one Bug Path: `a` is not 0, `b` is not 0."
2. Tick "Show constraints" under "Show arrows", then click line 6, `if (a == 0)`.
   The panel opens on Step 1.
   Point at `a`, whose range excludes 0, and at `p`, which still holds `&x`.
3. Type `a == 0` into "What if" and press Check.
   The verdict is Infeasible: the path dies at Step 1.
   Say: "My assumption rules out this path. But `a == 0` is exactly the other way to the bug, through line 7. That is why the verdict talks about this path, and adds that the bug may still be reachable through another path."
4. Optional, if asked about the other variable: remove the row, click line 8, `if (b != 0)`, and check `b == 0`.
   It dies at Step 2, and the bug is still there through `a`.

## Part 2: a real report from tmux (one to two minutes)

1. Open the tmux URL.
   It is `core.NullDereference` at `grid.c:1073` in `grid_string_cells`, with an eight-step Bug Path.
   Read the three steps that matter: Step 1 "Assuming 'lastgc' is equal to NULL" on line 1051, Step 7 on line 1072 where `flags & GRID_STRING_WITH_SEQUENCES` is taken, and Step 8, the dereference of `*lastgc`.
2. Say: "The analyzer looked at this function without its callers. There are two: `grid-view.c:234` passes `NULL` with flags 0, and `cmd-capture-pane.c:184` passes `&gc`. So I know: when `lastgc` is null, `flags` is 0."
3. Tick "Show constraints" and click line 1051.
   The panel shows Step 1 with `lastgc` as `null`.
4. Type `flags == 0` and press Check.
   The verdict is Infeasible and says it dies at Step 7.
5. Click "Step 7" in the verdict.
   The view jumps to line 1072 and the panel marks the step "Path dies here".
   Say: "My knowledge about the callers rules out this path exactly where the code tests the flag. The analyzer's path needed `flags` to have the sequences bit while `lastgc` is null, and no caller does that."
6. Close with the limits: Infeasible is about this path, not a proof that the bug is gone. The check uses Z3 over what the analyzer recorded, not a new analysis run.

## Part 3, optional: one line, two calls (one minute)

1. Open the several-contexts URL.
   `take` is called twice, on lines 13 and 14, and the Bug Path runs through `if (flag)` on line 5 in both calls.
2. Tick "Show constraints" and click line 5.
   The picker offers Step 3 and Step 8, told apart only by the range of `flag`.
   Say: "The source line, and the control flow graph too, are the same for both. What differs is the calling context."
3. Choose "Choose by analyzer state" at the foot of the picker.
   The view lists the analyzer states the Path Steps come from, grouped by stack frame: `take` called at line 13, then `take` called at line 14.
   It also counts the analyzer nodes between them that have no Path Step.
4. Click the `BlockEdge` state in the second `take` frame.
   The panel shows Step 8, "Assuming 'flag' is 0".

## If something goes wrong

- A blank report page or an old UI: run `dev-loop.sh web`, then reload without the cache.
- "server already listening": another server holds port 8002. `dev-loop.sh stop` stops the one the script started.
- The two URLs differ: use the ones `dev-loop.sh demo` printed. They come from the stored file and line, not from fixed IDs.
