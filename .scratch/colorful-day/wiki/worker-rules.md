# Worker rules

Related: [execution plan](execution-plan.md).

## 2026-11-10: rules given to every ticket worker

- Both repositories hold many unrelated untracked user files, as of `llvm-project@d417c2ac2026` and `codechecker@bae448521`, so workers stage explicit paths only and never run `git add -A`, `git clean`, stash or reset.
- Commits are terse, have no co-author or attribution trailer, and stay local. The spec and the user's global instructions both say so.
- Every ticket's web UI behavior is verified in a real browser with `chrome-devtools-axi`, and screenshots go under `/Users/efulop/colorful-day-env/screens/`.
- Costly traps go to Open Brain from the worker that found them.
- Workers begin with `DELEGATED_WORKER` and do not spawn further agents.

## 2026-11-10: model routing

On 2026-11-10 the session-start capacity probe showed Codex at 16% with a 15% reserve heuristic, so the lead chose native Claude subagents over Codex workers.

## 2026-11-10: tracked files after test runs

On 2026-11-10 the lead added a rule after a test run left tracked fixtures modified: workers check `git status` in both repositories before finishing, and report or restore any tracked file their test runs changed.
