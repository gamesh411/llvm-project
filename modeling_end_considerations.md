
Let me know if you prefer eventualities checked at EndFunction only (as now), or if we should encode an explicit End event in SPOT and recognize satisfaction within the monitor too.
what would be the practical difference between these choices?

Here’s the practical difference between the two options for “eventually free”:
a) Framework obligations checked at EndFunction
Diagnostic timing: Reports leaks exactly at function end (one clear point).
Complexity: Simple. No special APs or LTL changes; keeps SPOT focused on safety (e.g., double-free).
Semantics: Finite-trace by construction; matches CSA’s per-function path termination.
Reuse: Generic and checker-agnostic; no malloc/free specifics baked into the framework.
Performance: Minimal overhead; only a final sweep of PendingLeakSet.
b) Encode End as an AP in SPOT and use F φ ≤ End
Diagnostic timing: Still only provably violated at End (liveness needs a trace end), but the violation comes from SPOT, not the framework.
Complexity: Higher. You must inject an End event AP, adapt formulas, and reason about finite-trace LTL (or LTLf) acceptance; need to map function/scope ends to APs.
Semantics: Closer to a pure LTL-driven monitor, but you must carefully model which “End” (function, scope, path, analysis) you mean and ensure CSA actually hits it on all paths.
Reuse: Properties become End-aware (less plug-and-play unless you standardize “scope_end” APs for multiple granularities).
Performance: Slightly more APs and transitions per step; more logic in monitor setup.
Bottom line:
If you want a minimal, robust, reusable framework where the checker just states the malloc/free property, choose a). Let SPOT handle safety (double-free) online, and let the framework discharge eventualities at EndFunction.
Choose b) only if you want all obligations expressed purely in the LTL/monitor layer and are willing to add End APs and finite-trace semantics handling.