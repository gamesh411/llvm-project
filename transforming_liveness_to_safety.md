- Agreed: we’ll emit as soon as a symbol becomes dead; we won’t wait for end-of-analysis. If we still have active obligations at analysis end, we’ll emit a separate, clearly annotated diagnostic.

Implementation plan that fits the merged design and avoids duplicate logic
- Sentinel APs
  - ap_DEAD(x): true on DeadSymbols for that symbol.
  - ap_ENDANALYSIS(x): true during checkEndAnalysis for still-active symbols.
- Formula rewrite to make “eventually free” decidable online
  - Replace F free(x) with “free(x) must occur before a sentinel”:
    - F_before_sentinel free(x) ≡ (¬ap_DEAD(x) ∧ ¬ap_ENDANALYSIS(x)) U free(x).
  - This turns the obligation into a safety obligation that is decidable at the point the sentinel fires (DEAD or ENDANALYSIS).
- State-splitting
  - Keep splits, but only when IsNonNull(x) exists in the formula:
    - PostCall(ReturnValue x) and PreCall(param x) split on non-nullness only if IsNonNull(x) is present. We already gated splits on the formula’s IsNonNull.
- Driving diagnostics solely from the SPOT monitor
  - When stepping on a DEAD event:
    - If the monitor is in a state still “expecting” free(x) (i.e., the U-obligation hasn’t been fulfilled), emit “resource not destroyed before becoming unreachable”.
  - When stepping on ENDANALYSIS for still-active symbols:
    - If the monitor still expects free(x), emit “resource not destroyed before analysis end”.
  - No framework-side leak/double-free reports; all reports come from monitor state + event type.
- Minimal bookkeeping instead of PendingLeakSet
  - We can avoid PendingLeakSet if we:
    - Track symbols and their activity via `SymbolStates` (Active/Inactive).
    - At DeadSymbols: we already know the dying symbol; we just step SPOT with ap_DEAD for that symbol.
    - At EndAnalysis: iterate known `SymbolStates` entries and step SPOT with ap_ENDANALYSIS for those still Active.
  - This keeps a single source of truth (SPOT) while using `SymbolStates` only to enumerate candidates at EndAnalysis. If you prefer, we can keep a tiny “ActiveObligationSet” instead of reusing PendingLeakSet; functionally equivalent but smaller.

Labels and “smallest responsible subformula”
- We’ll take the smallest labeled node implicated by the violated subformula:
  - For leaks: the U-subformula node replacing F free(x) should carry the “leak” label; we emit that label.
  - For double-free: the G(free → G ¬free) branch should carry the “double free” label; we emit that label.
- We can later add the nearest labeled ancestor to provide context, but we’ll start with the smallest labeled node only as requested.

Is “no transition matched” the right violation criterion?
- Short answer: no. In a well-formed monitor, transitions should be total for every AP valuation; “no transition” usually indicates a modeling bug (e.g., AP dict mismatch), not a property violation.
- Correct online semantics
  - For safety properties (and safety-converted obligations like “free before DEAD/END”), a violation is witnessed by a finite bad prefix. In a deterministic monitor, that corresponds to reaching a rejecting (error) condition/state when a sentinel happens and the obligation is still pending.
  - For general LTL with liveness (plain F free), finite prefixes are typically inconclusive. Introducing sentinels (DEAD/ENDANALYSIS) converts the obligation into a safety condition at those events, enabling sound online detection.
- Practical approach
  - We should not rely on “no transition matched.” Instead, we (a) rewrite the formula with sentinels to make violation decidable at DEAD/END, and (b) detect violation by the monitor being in an “obligation-pending” region when the sentinel AP is true. This is consistent with runtime verification practice and avoids reliance on accidental automaton incompleteness.

What I’ll implement next, unless you object
- Add ap_DEAD(x), ap_ENDANALYSIS(x) evaluators.
- Rewrite the property to use the “before sentinel” U-form for eventually.
- Step SPOT on DeadSymbols and EndAnalysis and emit diagnostics from SPOT only, using smallest labeled node.
- Remove reliance on PendingLeakSet; enumerate via `SymbolStates` at EndAnalysis.
- Keep current IsNonNull-gated splits.

Please confirm:
- OK to rewrite F free(x) to “free before DEAD ∨ ENDANALYSIS” using U with both sentinels?
- OK to drop PendingLeakSet and enumerate Active from `SymbolStates` at EndAnalysis?
- OK to start with smallest labeled node only for messages?