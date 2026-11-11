# Colorful Day performance evaluation

Date: 2026-11-11.
Code: `llvm-project@91621edfefb9` (build `build-colorful`, Release, Z3 5.3.3) and `codechecker@63ec865ce` (dev package `build/CodeChecker`, thrift 0.25.0 in the venv).
Machine: Apple M2 Max, 12 cores, 32 GB.
Generated data, scripts and raw logs are in `/Users/efulop/colorful-day-env/perf/`.
Nothing in either repository was changed, and no mitigation was implemented.

## Summary

Constraint snapshots are repeated in full on every Path Step.
A step's path condition, its SMT-LIB and its variable list each grow with the path, so a trace costs O(steps x path length), which is quadratic in practice.
On tmux 3.5a this stays tolerable: 15.9 times the plist size, and 0.3 s more when a report opens.
On a synthetic 1205-step path it is not: a 215 MB plist, 44 s to store, 107 MB downloaded twice, 17 s until the page responds, and a crash in every Python Thrift client.

The three largest bottlenecks:

1. Redundant per-step data, which every later stage inherits: 9.4 MB of step lists on tmux, which are 0.41 MB delta-encoded, and only 479 distinct SMT assertions among 16,713 emitted.
2. Serving the whole trace through Thrift JSON on every report open: Python Thrift encoding takes 92% of server latency, the response has no gzip, and the page fetches it twice.
3. What-If and the UI reload and re-scan the whole trace on every action: 89% of a large check is re-parsing the trace, and `snapshotKey` takes about 30% of a step click on a 605-step path.

The cheapest high-impact fixes:

- a snapshot table keyed by analyzer node, with per-node and per-assertion caches in Clang;
- not fetching the trace twice;
- caching the parsed trace per report on the server;
- `shallowRef` and precomputed snapshot keys in the UI.

The format change that removes the quadratic growth is delta-encoding or interning the step lists, which belongs with lazy trace fetching in upstream hardening.

## Test inputs

- tmux 3.5a, the whole project as `dev-loop.sh demo` analyzes it: 146 TUs, 30 reports with a trace, 1278 steps, 35 steps median, 114 at most.
- Synthetic `longN.c` from `perf/scripts/gen_long_path.py N`: one null dereference after N parameter checks `if (aI != I+1) return`. The Bug Path has 3N+5 steps, and its path condition and visible variables grow by one per check. N = 25, 50, 100, 200, 400 give 80, 155, 305, 605 and 1205 steps.
- `perf/hard/r/hard.c`: a Bug Path whose condition is 64-bit factoring, meant to make Z3 slow. It did not (see stage 3).

## Bottleneck table

M means measured here, E means estimated from code or from measured counts, and P means from earlier ticket comments.

| # | Stage | Bottleneck | Cost | Scales with | How measured |
| --- | --- | --- | --- | --- | --- |
| 1 | Clang | SMT-LIB pretty-printing through Z3 for every snapshot | 345 of 415 ms snapshot CPU on `cmd-find.c` (83%) | steps x path-condition size | M: macOS `sample` of cc1, inclusive counts |
| 2 | Clang | Snapshots built for pieces that are later pruned, and rebuilt for the same node | 440 built, 377 distinct nodes, 114 emitted steps, 56 distinct emitted nodes | pieces before pruning | M: lldb breakpoint hit counts and argument registers |
| 3 | Clang | Analysis time per TU | `cmd-find.c` +47% (0.95 to 1.40 s), `grid.c` +6%, `window-copy.c` +4%; whole tmux within noise | steps x path condition | M: `/usr/bin/time`, 3 runs |
| 4 | Clang | Plist size | tmux 1.48 to 23.5 MB (15.9x); synthetic 1.15 to 215 MB at 1205 steps | about steps^2 (3.9x per doubling) | M: file sizes |
| 5 | Clang | Analyzer memory | +6% on `cmd-find.c`; 98 to 226 MB at 1205 steps | steps^2 | M: max RSS |
| 6 | Convert | Report converter parse + `convert()` + write, done once on the client | tmux 0.14 to 1.04 s; 215 MB plist 6.9 s + 5.0 s, 513 MB RSS | plist bytes, about 32 MB/s | M: `parse_bench.py`, `parse_rss.py` |
| 7 | Store | `CodeChecker store` wall time and client memory | tmux 7.45 to 8.23 s, 61 to 130 MB; 1205 steps 44 s, 1.9 GB | plist bytes | M: `/usr/bin/time` |
| 8 | Store | Hard ceiling on store size (thrift 0.25 string limit) | fails above about 12.3 MiB compressed zip; traces make tmux's zip 2.5x larger | compressed zip | M: failed store at 13.7 MiB |
| 9 | DB | Path-data blob | tmux +352 KB (18.5 KB to 370 KB); compression drops from 34-99x to 10x once a step exceeds zlib's 32 KB window | steps^2, then worse | M: sqlite blob sizes |
| 10 | Server | Thrift JSON encoding of `constraintTrace` | 92% of `getReportDetails` time: 3.14 of 3.40 s at 1205 steps, 67 of 75 ms for `window-copy.c` | trace bytes | M: `server_decomp.py` |
| 11 | Server | Payload over HTTP, no gzip, JSON-in-JSON escaping +13% | tmux median 230 KB (6.9 KB off), max 2.14 MB; 107 MB at 1205 steps | trace bytes | M: response sizes |
| 12 | Server | `checkWhatIf` re-reads and re-parses the trace on every call | 0.76 of 0.85 s per check at 1205 steps; solving under 0.1 s | trace bytes | M: `what_if_bench.py`, `server_decomp.py` |
| 13 | Server | API workers held by checks | 12 concurrent 0.85 s checks delay an unrelated call by up to 1.9 s; worst case 8 s per check by design | checks in flight | M: `worker_starvation.py`; E: 2000 + 2000 + 4000 ms from code |
| 14 | Server | Worker memory kept after large traces | 300-570 MB per worker, 5.7 GB over 25 processes after the 1205-step tests | largest trace a worker served | M: `ps` RSS |
| 15 | Clients | Python Thrift decode of the trace, and the 16,384,000-character limit | 2.7 / 10.9 / 42.6 s at 305 / 605 / 1205 steps; `cmd results --details` 0.5 to 10 s on tmux and crashes at 605 steps | trace bytes | M: `raw_details.py`, `cmd results` |
| 16 | Web UI | `getReportDetails` fetched twice per open (`Report.vue` and `ReportTree.vue`) | 2x transfer, 2x decode | trace bytes | M: Resource Timing |
| 17 | Web UI | Page ready time and main-thread long tasks | 1.33 s off; 2.25 s `window-copy.c`; 4.47 s at 605 steps (two tasks of 2.0 and 1.5 s); 17.0 s at 1205 steps | trace bytes | M: Chrome trace, polling |
| 18 | Web UI | Step click, CFG and States open | click 18-48 ms on tmux, 290-438 ms at 605 steps; CFG 677 ms, States 629 ms at 605 steps | steps x snapshot size | M: click to next frame; JS CPU profile |
| 19 | Web UI | `snapshotKey` runs `JSON.stringify` through Vue reactive proxies on every comparison | 357 ms self + about 80 ms proxy traps of a 1.39 s click-and-CFG profile | steps x snapshot size | M: CPU profile |
| 20 | Web UI | JS heap | peak 157 MB (`window-copy.c`), 693 MB (605 steps), 2.4 GB (1205 steps); after GC 56 / 104 / 191 MB | trace bytes | M: `performance.memory`, `--expose-gc` |

## Stage 1: Clang emission

### Time and memory

Per TU, three runs each with the exact command CodeChecker uses (`perf/clang/cmds-on.sh`, Z3 refutation on):

| TU | reports, steps | off median (s) | on median (s) | change | max RSS off / on (MB) | plist off / on (bytes) |
| --- | --- | --- | --- | --- | --- | --- |
| `cmd-find.c` | 1, 114 | 0.95 | 1.40 | +47% | 144 / 153 | 123,134 / 2,634,803 |
| `grid.c` | 3, 142 | 4.71 | 5.00 | +6% | 184-211 / 164-178 | 149,426 / 2,152,056 |
| `window-copy.c` | 2, 118 | 10.20 | 10.59 | +4% | 212-223 / 206-238 | 121,734 / 3,208,625 |

Whole tmux with `-j12`, three runs each, user CPU: off 194.6, 192.5, 182.2 s, on 202.8, 189.9, 189.0 s.
Wall time: off 34.1, 31.3, 29.1 s, on 33.8, 29.7, 30.2 s.
That is within run-to-run noise, consistent with the 1.4% that ticket 08 measured (P).
Whole-project numbers hide the per-TU cost because most TU time is path exploration, while emission cost tracks path length: one 114-step report adds 0.45 s.

Synthetic paths, one run each (`perf/synth/clang.tsv`):

| N | steps | off (s) | on (s) | max RSS off / on (MB) | plist off / on |
| --- | --- | --- | --- | --- | --- |
| 25 | 80 | 0.03 | 0.09 | 60 / 62 | 77 KB / 1.1 MB |
| 50 | 155 | 0.03 | 0.27 | 62 / 66 | 148 KB / 3.8 MB |
| 100 | 305 | 0.04 | 1.00 | 65 / 80 | 291 KB / 14.2 MB |
| 200 | 605 | 0.12 | 2.41 | 73 / 107 | 577 KB / 54.7 MB |
| 400 | 1205 | 0.62 | 10.33 | 98 / 226 | 1.1 MB / 215 MB |

Size grows 3.9x for each doubling of the path, so it is quadratic.

### Where the time goes

`sample` of the `cmd-find.c` cc1 with emission on (1 ms interval, `perf/clang/sample-cmd-find-on.txt`):

- `makeConstraintSnapshot`: 415 samples, against 632 for `ExecuteWorkList`, the path exploration.
- Of those 415, `Z3Expr::print` takes 302 and `Z3Sort::print` 43, so 83% is SMT-LIB pretty-printing in `addSMTLIB` (inlined).
- `getCrosscheckRangeConstraint` (building the Z3 terms) takes 28 and `renderConstraints` (range dumps) 16.
- Variables, globals, CFG position, node description, `recordPathHistory`, `renderPathCFGs` and the plist writer each take under 5.

How often snapshots are built (lldb, `perf/clang/lldb-nodes.log`):

- `makeConstraintSnapshot` ran 440 times for one report.
- It got 377 distinct nodes, while the plist has 114 steps whose snapshots come from 56 distinct nodes (`exploded_nodes`).
- So 74% of snapshots belong to pieces that `optimizeEdges` and pruning later drop, and the steps that are kept repeat each node's snapshot about twice (1278 steps, 674 nodes on all of tmux).

How much of the SMT-LIB is new (`perf/scripts/smt_redundancy.py`):

- tmux emits 16,713 assertions, of which 479 are distinct, and 18,541 declarations, of which 671 are distinct.
- The 605-step synthetic path emits 61,505 assertions, of which 201 are distinct, and 121,605 declarations, of which 201 are distinct.
- Each step re-prints the whole accumulated path condition, which is the quadratic term.

### What the plist holds

Compact JSON bytes of tmux traces by component (`perf/trace_sizes_tmux.json`), 11.5 MB in total, written as about 22 MB of plist XML:

| component | bytes | share |
| --- | --- | --- |
| step `path_condition` | 3,124,294 | 27% |
| step `symbol_ranges` | 2,385,137 | 21% |
| step `smt_assertions` | 1,919,057 | 17% |
| `cfgs` | 1,498,579 | 13% |
| step `variables` | 1,170,471 | 10% |
| step `smt_declarations` | 805,671 | 7% |
| `exploded_nodes`, `stack_frames`, step `cfg_position`, `exploded_node`, `order`, `path_index` | 205,295 | 2% |

On the 605-step synthetic path, `variables` dominates (11.4 MB of 23.8 MB), because every parameter is listed at every step.

What the step lists would shrink to, computed from the same data and not implemented:

- tmux: 9.40 MB as now, 1.84 MB with each distinct list value stored once, and 0.41 MB delta-encoded against the previous step (23x).
- 605 steps: 21.98 MB as now, 1.84 MB stored once, and 0.08 MB delta-encoded (264x).
- Interning strings alone takes tmux from 8.26 MB to 0.55 MB of strings.
- The CFGs repeat little: 110 CFGs come from 98 distinct functions, so sharing them per file would save about 11%.

### Non-determinism

Three runs of `window-copy.c` gave different plists: symbol dumps such as `conj_$27{void *, LC331, S308970, #1}` carry location-context IDs that change between runs (LC331, LC329, LC118), and the file size moved by 2 KB.
That defeats byte-level diffing and caching of plists, and any deduplication across runs.

## Stage 2: report conversion and store

Report converter, all of tmux (`perf/parse_bench_{off,on}.json`):

- Off: parse 0.09 s, `convert()` + write 0.05 s, path-data JSON 165 KB, compressed 18.5 KB.
- On: parse 0.61 s, `convert()` + write 0.43 s, server JSON + zlib 0.19 s, path-data JSON 12.4 MB, compressed 370 KB.

Large plists (`perf/synth/parse.tsv`, one process per plist):

| plist | parse (s) | convert + write (s) | max RSS (MB) |
| --- | --- | --- | --- |
| 14.2 MB | 0.47 | 0.34 | 60 |
| 54.7 MB | 1.77 | 1.28 | 152 |
| 215 MB | 6.94 | 4.97 | 513 |

`CodeChecker store` against a fresh server (`perf/store.tsv`, `perf/logs/store-*.log`):

| run | wall (s) | client max RSS (MB) | zip raw / compressed | server "Store reports" (s) |
| --- | --- | --- | --- | --- |
| tmux off | 7.45 | 61 | 2.1 MiB / 206 KiB | 0.09 |
| tmux on | 8.23 | 130 | 22.4 MiB / 516 KiB | 0.80 |
| 305 steps | 8.49 | 165 | 15.2 MiB / 772 KiB | 0.59 |
| 605 steps | 14.51 | 511 | 58.6 MiB / 2.9 MiB | 2.47 |
| 1205 steps | 44.22 | 1887 | 230.2 MiB / 11.3 MiB | 9.86 |
| 1325 steps (N=440) | failed after 38.5 | - | 278.2 MiB / 13.7 MiB | - |

The 1205-step store spends 17 s parsing in the pool (Report objects come back to the parent pickled), 5 s converting, 3 s compressing, 8 s uploading and 10 s storing on the server.
About 6.5 s of every store is fixed overhead.

The failed store ended in "Internal server error: Length exceeded max allowed: 16384000".
The server reads `massStoreRun`'s base64 zip with `TJSONProtocolFactory()`, and the venv's thrift 0.25.0 (allowed by `thrift~=0.22`) limits a string to 16,384,000 characters by default.
So a store fails once its compressed zip exceeds about 12.3 MiB.
That limit predates Colorful Day, but traces make tmux's compressed zip 2.5 times larger, so a project with a 4.9 MiB zip with emission off would hit it (E).

Database:

- tmux with traces adds about 352 KB to the path-data blobs (18.5 KB to 370 KB), and the whole trace JSON compresses 34x (11.5 MB to 339 KB).
- The 305-step blob is 69 KB for 6.86 MB of JSON (99x), the 605-step one 2.66 MB for 27.0 MB (10x) and the 1205-step one 10.8 MB for 107 MB (10x).
- The drop happens because zlib's window is 32 KB: once one step's snapshot is larger than that, the identical previous step is out of reach and compression stops removing the repetition.

## Stage 3: server

`getReportDetails` over HTTP, median of 5 calls (`perf/api_tmux.jsonl`, `perf/api_synth.jsonl`, `perf/raw_details_synth.txt`):

| report | steps | response bytes | latency |
| --- | --- | --- | --- |
| tmux, emission off, median | - | 6,908 | 2.9 ms |
| tmux, median of 30 | 35 | 230,044 | 10.7 ms |
| tmux `window-copy.c:3723` | 97 | 2,139,707 | 75 ms |
| synthetic | 305 | 6,870,240 | 0.22-0.30 s |
| synthetic | 605 | 27,021,559 | 0.86-1.26 s |
| synthetic | 1205 | 107,359,986 | 3.40 s |

No response carried a `Content-Encoding`, even with `Accept-Encoding: gzip`.
The trace is a JSON string inside Thrift JSON, so escaping adds 13% (95.0 MB trace, 107.2 MB response).

Where the time goes (`perf/server_decomp_*.jsonl`, best of 3, in-process on the stored blob):

| step | 97 steps (`window-copy.c`) | 1205 steps |
| --- | --- | --- |
| zlib decompress | 0.3 ms | 33 ms |
| `json.loads` of the path data | 2.7 ms | 181 ms |
| Thrift JSON encoding of `ReportDetails` | 67 ms | 3,138 ms |

Python clients pay the same in reverse: decoding one response took 2.7 s, 10.9 s and 42.6 s at 305, 605 and 1205 steps.
`CodeChecker cmd results --details -o json` took 0.53 s with emission off and 9.99 s with it on for tmux, and its output grew from 293 KB to 12.6 MB.
At 605 steps it crashes with "Length exceeded max allowed: 16384000", because the client's `TJSONProtocol` has the same default limit and the trace string is 23.8 MB.
The web UI's JavaScript Thrift has no such limit.

`checkWhatIf`, median of 3 (`perf/what_if_*.jsonl`):

| report | check | verdict | latency |
| --- | --- | --- | --- |
| tmux `grid.c:1073` | `flags == 0` at the first step | Infeasible, dies at order 22 | 20 ms |
| tmux `grid.c:1073` | `flags != 0` | Feasible | 12 ms |
| synthetic, 80 steps | four kinds | as expected | 18-31 ms |
| synthetic, 305 steps | four kinds | as expected | 97-113 ms |
| synthetic, 605 steps | four kinds | as expected | 289-352 ms |
| synthetic, 1205 steps | `a0 == 1` | Feasible | 838 ms |
| synthetic, 1205 steps | `a0 == 2`, dies at order 2 | Infeasible | 853 ms |
| synthetic, 1205 steps | `a399 == 0`, dies at order 1199 | Infeasible | 902 ms |
| synthetic, 1205 steps | `a3 != 4` throughout | Infeasible | 870 ms |
| factoring path, 23 steps | four checks | as expected | 73-148 ms |

Every check reloads the report details, so it decompresses and parses the path data and then `json.loads` the trace a second time.
It also rebuilds the `_Path` index, creates a Z3 context, re-parses every declaration for each term, and solves the Baseline Verdict again.
At 1205 steps the set-up alone measured 33 + 181 + 357 + 188 ms, which is 89% of the 853 ms check.
Z3 context creation (0.4 ms) and parsing the last step's SMT-LIB (0.5 ms) were negligible on every input.

None of the checks came near the 2000 ms per-call timeout.
Z3 even solved the 64-bit factoring path in under 150 ms, so a slow query would need deliberate construction.
The worst case of 2000 + 2000 + 4000 ms = 8 s per check is therefore from the code, not reproduced.

API worker occupancy, a cheap `getRunData` probe while N concurrent 1205-step checks run on a server with 12 API workers (`perf/worker_starvation.jsonl`):

| concurrent checks | probe max | probe median | check median |
| --- | --- | --- | --- |
| 1 | 5 ms | 4 ms | 0.84 s |
| 12 | 1.93 s | 8 ms | 2.28 s |
| 24 | 2.66 s | 4 ms | 2.86 s |

After the 1205-step tests, server workers held 300-570 MB each (5.7 GB over 25 processes), because CPython keeps the heap it grew for the decoded strings.

## Stage 4: web UI

Chrome headless at 1200 px through `chrome-devtools-axi`, against the perf server.

`Report.vue` and `ReportTree.vue` both call `getReportDetails` for the opened report, so the trace is downloaded and decoded twice (two 217,139-byte responses for `grid.c:1073`, two 107 MB ones at 1205 steps).

Page load, from navigation start until the "Show constraints" toggle and the tree are ready (`perf/ui/heap.tsv`, traces `perf/ui/trace-*.json.gz`):

| report | ready (ms) | long tasks caused by details (ms) | JS heap at load / after GC (MB) |
| --- | --- | --- | --- |
| tmux `grid.c:1073`, emission off | 1332 | none | 59 / 50 |
| tmux `grid.c:1073` | 1362-1563 | 75, 52 (same as off) | 52 / 50 |
| tmux `window-copy.c:3723` | 2253 | 209, 124, 88 | 157 / 56 |
| synthetic, 305 steps | 2985 | 746, 362, 359 | 381 / 76 |
| synthetic, 605 steps | 4473 | 1978, 1515 | 693 / 104 |
| synthetic, 1205 steps | 17004 | not captured (the trace stopped first) | 2435 / 191 |

The long tasks are the XHR handlers: Thrift JSON string decoding, `JSON.parse`, and minor GC (726 ms of the 1978 ms task).

Interactions, from click to the next frame (`perf/ui/interact.tsv`):

| report | toggle | select first / middle / last step | open CFG | open States |
| --- | --- | --- | --- | --- |
| tmux `grid.c:1073` (26 steps) | 11 ms | 48 / 18 / 43 ms | 26 ms | 26 ms |
| tmux `window-copy.c` (97 steps) | 16 ms | 102 / 133 / 83 ms | 14 ms | 29 ms |
| 305 steps | 23 ms | 235 / 321 / 224 ms | 197 ms | 173 ms |
| 605 steps | 25 ms | 290 / 438 / 353 ms | 677 ms | 629 ms |

A CPU profile of one step click plus a CFG open at 605 steps (`perf/ui/click-66.json.gz`, 1388 ms sampled) puts 357 ms of self time in the minified `ca`.
That is `snapshotKey`, which runs `JSON.stringify([symbol_ranges, variables, path_condition])` for every comparison in `oneChoicePerSnapshot`, through the reactive proxies of `ref(constraintTrace)`.
Another 80 ms or so goes to the proxy traps `get`, `ownKeys` and `track`.
`constraintSymbolNames` also filters and sorts every step on each selection, and `displayedStep` re-filters every step through `pathStepsOnLine`.

Seen along the way, not related to performance:

- At 1200 px the snapshot panel's "Other symbols" list wraps a long symbol dump one character per line (`grid.c:1073`, Step 8), because the range column takes the width.
- The 1205-step page logged "Calls to EditorView.update are not allowed while an update is in progress" once. Not investigated.

## Stage 5: other findings

- `getRunResults` with `getDetails` (`cmd results --details`, exports) returns every report's trace. See stage 3.
- The quadratic term comes from Clang, not from loops in CodeChecker: each step's snapshot is complete, and SMT-LIB and declarations are re-emitted per step although `what_if._Path` immediately takes the union of all declarations.
- `_bitvector_term` re-parses the union of all declarations for each term, and "holds throughout" does so for each distinct value. That is O(terms x declarations), which is small on every input measured.
- A syntax error in a What-If Constraint still runs the Baseline Verdict.
- The store client keeps the whole plist, its Report objects and the base64 zip in memory, which is why one 215 MB plist needs 1.9 GB.

## Mitigations

Ranked by impact against effort.
Impact estimates are computed from the measured counts above and were not implemented.

| rank | mitigation | removes | expected effect | effort | fits |
| --- | --- | --- | --- | --- | --- |
| 1 | Clang: build snapshots lazily at plist time, cache them per `ExplodedNode`, and cache each printed assertion and declaration by symbol and range within a report | 1, 2, 3 | 440 builds to 56 and 16,713 assertion prints to 479; `cmd-find.c` overhead from +47% to an estimated few % | low, all in `BugReporter.cpp` | prototype |
| 2 | Plist: a snapshot table per report keyed by analyzer node, with steps pointing to it, as `exploded_node` already does | 4-20 in part | 1278 snapshots to 674 on tmux (1.9x everywhere downstream) | low to medium: Clang writer, parser and `convert()`, What-If and UI lookups | prototype |
| 3 | UI: fetch the details once (the tree gets them from `Report.vue` or leaves the trace out) | 16, half of 17 and 20 | halves transfer and decode time; removes the 1.5 s second task at 605 steps | low | prototype |
| 4 | UI: hold the trace in `shallowRef` or `markRaw`, and compute each step's snapshot key once, or use the node index as the key since equal nodes give equal snapshots | 18, 19 | removes about 440 ms of a 605-step click-and-CFG; clicks become independent of snapshot size | low | prototype |
| 5 | Server: cache the parsed trace, `_Path`, parsed Z3 assertions and Baseline Verdict per report in each worker (small LRU keyed by report ID) | 12 | 1205-step checks from 0.85 s to about 0.1 s after the first | low | prototype |
| 6 | Format v2: per-step lists as deltas from the previous step (path condition only narrows), with strings interned per report and SMT declarations once per report | 4-12, 15, 17, 20 | step lists 23x smaller on tmux (9.40 to 0.41 MB) and 264x at 605 steps; growth becomes linear | medium to high: every stage reconstructs or is rewritten | upstream (a prototype could try it behind `version: 2`) |
| 7 | Lazy fetching: `getReportDetails` without the trace, and a separate `getConstraintTrace` or per-step `getConstraintSnapshot(reportId, order)` called only when "Show constraints" is on | 10, 11, 15-17, 20 | report pages and `cmd results --details` cost the same as with emission off; one step at a time stays small | medium: API change, UI state | upstream |
| 8 | Transport: gzip for API responses, or serve the trace as raw JSON outside Thrift | 10, 11, 15 | the trace compresses 34x on tmux; no Python string encoding | medium: server and client changes | upstream |
| 9 | Run What-If in a bounded pool or task worker with its own concurrency limit and a per-user rate limit | 13 | API workers stay free; worst case no longer 8 s per worker | medium | upstream |
| 10 | Emit SMT-LIB only at the last step plus per-step deltas, or only on demand by a `--emit-smtlib` sub-option | 1, part of 4 | SMT is 24% of the trace bytes on tmux, 30% at 605 steps | low in Clang; the What-If search must reconstruct per-step sets | upstream |
| 11 | Size guard: cap a trace by steps or bytes, mark it truncated, and refuse What-If on it | 8, 15, 17 | no store failures or client crashes from one long path | low | prototype safety net, upstream policy |
| 12 | Compact CFG encoding (an array per element) and CFGs once per file | part of 4 | CFGs are 13% of tmux trace JSON; sharing saves about 11% of that | low to medium | upstream |
| 13 | Deterministic symbol dumps (drop or renumber `LC` and `S` IDs) | non-determinism | stable plists for diffing, caching and cross-run dedup | medium, touches analyzer dump format | upstream |
| 14 | Streaming store and thrift `string_length_limit` set explicitly on server and clients | 7, 8, 15 | bounded memory; no silent 16 MB ceiling | medium | upstream, mostly independent of Colorful Day |

## What was measured and what was estimated

Measured: everything in the stage sections, except where marked otherwise.

Estimated, not measured:

- Whole-project emission overhead: three runs per mode stayed within noise, so only an upper bound of a few % is supported.
- The 8 s worst case per What-If check, which comes from the timeouts in `what_if.py`; no input made Z3 slow.
- The project size at which `store` hits the thrift limit: 2.5 x the off zip measured on tmux, extrapolated.
- Every mitigation's effect: computed from measured counts (snapshot builds, distinct strings, delta sizes), with no implementation.

Not measured:

- PostgreSQL, since only SQLite was used.
- Concurrent stores.
- A browser on a slow network, where the missing gzip would matter more.
- Firefox.

## Environment note

At 10:18 on 2026-11-11 a Homebrew upgrade outside this evaluation moved `/opt/homebrew/opt/z3` from 5.3.3 to 5.4.0.
`build-colorful/bin/clang` links `/opt/homebrew/opt/z3/lib/libz3.5.3.dylib` and now fails to start.
The runs after that used `DYLD_LIBRARY_PATH=/opt/homebrew/Cellar/z3/5.3.3/lib`, which works only until `brew cleanup` removes the old keg.
`dev-loop.sh analyze`, `fixture`, `lit` and `demo` need either that variable, a rebuild against 5.4.0, or `brew pin z3`.
The running demo server is unaffected, because What-If uses the venv's Python `z3-solver`.

## Reproducing

All paths are under `/Users/efulop/colorful-day-env`.
Activate the venv, put the Colorful Day Clang first on `PATH`, and set the z3 workaround while it is needed:

```sh
cd /Users/efulop/colorful-day-env
source venv/bin/activate
export PATH=/Users/efulop/llvm-project/build-colorful/bin:$PATH
export DYLD_LIBRARY_PATH=/opt/homebrew/Cellar/z3/5.3.3/lib
CC=/Users/efulop/codechecker/build/CodeChecker/bin/CodeChecker
PY=/opt/homebrew/bin/python3.13
```

Stage 1:

```sh
# Commands CodeChecker runs for three TUs (cdb3.json holds them).
$CC analyze perf/clang/cdb3.json -o perf/clang/cc-out --analyzers clangsa -j1 \
  --z3-refutation on --analyzer-config clangsa:emit-constraint-snapshots=true \
  --verbose debug_analyzer > perf/clang/cc-debug.log 2>&1
grep -- '--analyze' perf/clang/cc-debug.log > perf/clang/cmds-on.sh
perf/scripts/clang_bench.sh 3                       # perf/clang/bench.tsv
# Whole tmux, CPU time; repeat for off without the --analyzer-config.
/usr/bin/time -l $CC analyze projects/tmux/compile_commands.json -o perf/tmux-on \
  --analyzers clangsa -j12 --z3-refutation on \
  --analyzer-config clangsa:emit-constraint-snapshots=true
# Profile: cc1 command from `-###`, then sample it.
bash perf/clang/cc1-cmd-find-exec.sh & sleep 0.1; sample $! 2 1 -file perf/clang/sample-cmd-find-on.txt
$PY -I perf/scripts/sample_inclusive.py perf/clang/sample-cmd-find-on.txt makeConstraintSnapshot ExecuteWorkList
$PY -I perf/scripts/sample_children.py perf/clang/sample-cmd-find-on.txt makeConstraintSnapshot
# Snapshot builds and distinct nodes (see perf/clang/lldb-nodes.txt).
(cd projects/tmux && eval "set -- $(tail -1 ../../perf/clang/cc1-cmd-find-exec.sh | sed 's/^exec  *//')" \
  && lldb -b -s ../../perf/clang/lldb-nodes.txt -- "$@" > ../../perf/clang/lldb-nodes.log 2>&1)
grep -E '^ +x2 = ' perf/clang/lldb-nodes.log | sort -u | wc -l
# Sizes and redundancy.
$PY -I perf/scripts/trace_sizes.py reports-tmux reports-tmux-off
$PY -I perf/scripts/smt_redundancy.py reports-tmux/*.plist
# Synthetic paths: run clang inside each perf/synth/rN directory.
$PY -I perf/scripts/gen_long_path.py 400 > perf/synth/r400/long400.c
(cd perf/synth/r400 && /usr/bin/time -l clang --analyze --analyzer-output plist-multi-file \
  -Xclang -analyzer-checker=core -Xclang -analyzer-config -Xclang crosscheck-with-z3=true \
  -Xclang -analyzer-config -Xclang emit-constraint-snapshots=true -o long400.plist long400.c)
```

Stage 2:

```sh
venv/bin/python perf/scripts/parse_bench.py perf/tmux-on on
/usr/bin/time -l venv/bin/python perf/scripts/parse_rss.py perf/synth/r400/long400.plist convert
# Own server, not the demo one on 8002.
$CC server -w perf/server-ws --host localhost --port 8013 &
/usr/bin/time -l $CC store perf/synth/r400 -n perf-synth-r400 --url http://localhost:8013/Default
sqlite3 -readonly perf/server-ws/Default.sqlite \
  'select report_id, length(path_data) from report_path_data order by 2 desc limit 5'
```

Stage 3 (report IDs as the perf server assigned them: tmux on is run 2, `grid.c:1073` is 35, `window-copy.c:3723` is 33, synthetic 305/605/1205 steps are 65/66/67):

```sh
venv/bin/python perf/scripts/api_bench.py http://localhost:8013/Default perf-tmux-on
venv/bin/python perf/scripts/raw_details.py http://localhost:8013/Default 67 decode
venv/bin/python perf/scripts/server_decomp.py perf/server-ws/Default.sqlite 33 35 65 66 67
venv/bin/python perf/scripts/what_if_bench.py http://localhost:8013/Default perf/server-ws/Default.sqlite 67 \
  '[["dies early","first","a0 == 2",false]]'
venv/bin/python perf/scripts/worker_starvation.py http://localhost:8013/Default 67 0 "a0 == 2" 12
$CC cmd results perf-synth-r200 --details --url http://localhost:8013/Default -o json
```

Stage 4:

```sh
export CHROME_DEVTOOLS_AXI_SESSION=perf-gc CHROME_DEVTOOLS_AXI_CHROME_ARGS=--js-flags=--expose-gc
chrome-devtools-axi open "http://localhost:8013/Default/report-detail?report-id=66"
chrome-devtools-axi perf-start --file perf/ui/trace-66.json.gz
$PY -I perf/scripts/trace_tasks.py perf/ui/trace-66.json.gz 30
chrome-devtools-axi eval "$(cat perf/scripts/ui_interact.js)"
chrome-devtools-axi perf-start --no-reload --no-auto-stop   # then click, then:
chrome-devtools-axi perf-stop --file perf/ui/click-66.json.gz
$PY -I perf/scripts/trace_js_profile.py perf/ui/click-66.json.gz
```

Stop the perf server with `kill` on its wrapper PID, and wait for the port to close, as `dev-loop.sh stop` does.
