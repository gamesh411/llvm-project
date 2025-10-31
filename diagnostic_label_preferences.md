[3 tools called]

I'll quickly inspect the DSL AST node types to target labels on 'Eventually' vs 'No double free', then adjust the label selection logic to pick the smallest relevant labeled node (eventually for leak, no-double-free for double-free), and rebuild and run the tests.

[3 tools called]

I'll update the diagnostic label selection to prefer the appropriate subformula labels: for leaks, prefer the Eventually/Until label; for double-free, prefer the Implies label from the RHS. Then I'll rebuild and run the three tests to verify the messages.

[2 tools called]

I attached labels to the formula nodes and wired diagnostics to use them dynamically.

- I set labels in the property builder: `F free(x)` now uses “resource not destroyed (violates exactly-once)” and the no-double-free consequent uses “resource destroyed twice (violates exactly-once)”.
- Diagnostics now prefer the smallest relevant labeled node from the RHS of the top-level implication when emitting:
  - On leak (DeadSymbols/EndAnalysis with pending obligation), we pick the label from a labeled Eventually/Until node if present; otherwise any labeled descendant; fallback to the default leak text.
  - Double-free retains the specific label when freeing an already Inactive symbol.
- I preserved the “internal symbol: sym_N” suffix and note-tag binding for path context.

Status: Rebuilt and ran all three test variants; labels are used in the messages and behavior still matches expectations.

- leak_missing_free: emits “resource not destroyed (violates exactly-once) (internal symbol: sym_2)”.
- double_free: emits “resource destroyed twice (violates exactly-once) (internal symbol: sym_2)”.
- ok_exactly_once: no warning.

Would you like me to further bias the label picker to always choose the deepest labeled node (strict “smallest” in the tree) instead of prioritizing the temporal node first?

======


I'll implement a shared label selection helper and wire the double-free diagnostic to use it; then rebuild and run all three tests.

[3 tools called]

- Wired double-free diagnostics to use the same label-selection rule. Now it picks the smallest labeled subformula under the RHS, preferring Globally (G ¬free(x)) and otherwise the enclosing Implies. Tests still pass and messages remain as expected.

Answers

1) What does this mean for double-free? Where should DSL users put labels if they want them to appear?
- Put the label on the “no second free” part of the RHS of the top-level implication:
  - Prefer labeling the smallest subformula that directly expresses the constraint, i.e., G(!(free(x))). This is selected first.
  - Alternatively, label the enclosing Implies subformula free(x) -> G(!(free(x))) if you want a more general message. This is the fallback if G(!(free(x))) has no label.
- If neither is labeled, we fall back to the default “resource destroyed twice (violates exactly-once)”.

2) Where can they put labels if they want temporal violations to be diagnosed?
- For temporal obligations (leak/missing free), label the RHS obligation subformula:
  - Prefer labeling the Eventually/Until node that requires free(x) to occur. We select the smallest labeled subformula within the RHS, preferring the temporal node (Eventually/Until). If none is labeled, we fall back to any labeled RHS subformula; if none, we use the default “resource not destroyed (violates exactly-once)”.

Generic guidance on diagnostic label preferences
- Safety vs liveness (with sentinel rewrite):
  - Safety (e.g., double-free): The violation is decidable online at the instant the bad event happens. We attribute diagnostics to the smallest labeled subformula that directly encodes the safety constraint. For double-free, that’s G(!(free(x))) (preferred), or its nearest labeled ancestor (e.g., free(x) -> G(!(free(x)))).
  - Liveness transformed to safety (e.g., leak): We rewrite F free(x) into (!ap_DEAD(x) && !ap_ENDANALYSIS(x)) U free(x). The obligation ends when ap_DEAD(x) or ap_ENDANALYSIS(x) fires while free(x) hasn’t occurred. At that point, we attribute the diagnostic to the smallest labeled subformula within the RHS that encodes the obligation, preferring the temporal node (Eventually/Until) because it represents the obligation boundary.

Practical labeling tips
- Double-free: label G(!(free(x))) for the most specific message; add a broader label on free(x) -> G(!(free(x))) if you want a higher-level message when the inner node isn’t labeled.
- Leak/missing free: label F free(x) (or the rewritten Until form) for precise obligation messages; you can also label the RHS conjunction if you want a combined message for multiple obligations.

All three tests pass; labels now drive messages consistently for both leak and double-free.

rephrasing the above:
Answer to the two questions (generic)
- Where should users put labels for double-free?
  - Put labels on the smallest RHS subformula that encodes “no second free,” ideally on G(!(free(x))) (preferred). As a fallback, labeling the enclosing free(x) -> G(!(free(x))) also works. The message selection prefers the deepest labeled node among {G, Implies} on the RHS, then any RHS label, then the default.
- Where should users put labels for temporal violations (e.g., leak/missing free)?
  - Put labels on the RHS obligation subformula F free(x) (internally rewritten to a safety Until with Dead/EndAnalysis sentinels). We pick the smallest labeled subformula on the RHS, preferring the temporal node that represents the obligation boundary (Eventually/Until). If none present, we fall back to any RHS label, else default.
- Why the difference?
  - Safety property (double-free): The violation is instantaneously decidable at the event that breaks the rule. We attribute to the smallest labeled subformula that encodes the safety constraint (prefer G(!(free(x))) since it’s the immediate rule; fall back to its nearest labeled ancestor like Implies).
  - Liveness property rewritten to safety (leak): We convert F free(x) into a safety Until guarded by sentinels (ap_DEAD/ap_ENDANALYSIS) so that the violation becomes decidable when the sentinel fires without the witnessing event. At that moment, we attribute to the smallest labeled subformula that encodes the temporal obligation (prefer Eventually/Until), ensuring diagnostics reflect the temporal obligation itself.