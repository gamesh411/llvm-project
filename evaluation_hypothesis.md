# Evaluation Hypothesis for TEST_OK Case (UPDATED)

## LTL Formula
```
G( malloc(x) ∧ x ≠ null → F free(x) ∧ G( free(x) → G ¬free(x) ) )
```

## Key Changes Made
- **IsNonNull is now a BindingType flag** instead of a separate formula element
- **malloc** uses `ReturnValueNonNull` binding type
- **free** uses `FirstParameter` binding type
- **No separate `__isnonnull` AP** - the non-null constraint is built into the malloc AP

## Expected Evaluation Order for TEST_OK Case

### 1. **malloc call** (PostCall event)
- **AP Evaluation**:
  - `ap_1` (malloc(x) with ReturnValueNonNull) = TRUE
  - `ap_2` (free(x)) = FALSE
- **State Transition**: 0 → 1 (waiting for free)
- **Symbol Tracking**: Add symbol to tracked set on non-null branch only
- **State Splitting**: Yes, because binding type is `ReturnValueNonNull`

### 2. **free call** (PreCall event)
- **AP Evaluation**:
  - `ap_1` (malloc(x)) = FALSE
  - `ap_2` (free(x)) = TRUE
- **State Transition**: 1 → 2 (obligation fulfilled)
- **Symbol Tracking**: Remove symbol from tracked set
- **State Splitting**: No, this is a PreCall event

### 3. **End of function** (EndFunction event)
- **AP Evaluation**:
  - `ap_1` (malloc(x)) = FALSE
  - `ap_2` (free(x)) = FALSE
- **State Transition**: Stay in state 2 (accepting state)
- **Result**: No violation reported

## Key Assumptions

1. **State Splitting**: Only occurs for PostCall events with `ReturnValueNonNull` binding type
2. **Symbol Tracking**: Symbols are only added to tracked set on the non-null branch after state splitting
3. **AP Matching**: Each AP has a corresponding ASTMatcher that correctly identifies the relevant function calls
4. **Automaton States**: 
   - State 0: Initial state
   - State 1: Waiting for free (after malloc + non-null)
   - State 2: Obligation fulfilled (after free)
5. **Transition Conditions**: BDD conditions should match the expected AP valuations
6. **IsNonNull Logic**: Built into the binding type, not a separate AP

## Expected Trace Output (UPDATED)

```
[EDSL][INIT] Registered AP 1 binding: symbol='x' type=3
[EDSL][INIT] Registered AP 1 matcher for event matching
[EDSL][INIT] Registered AP 2 binding: symbol='x' type=1
[EDSL][INIT] Registered AP 2 matcher for event matching

[EDSL][AP_EVAL] Starting AP evaluation for call event
[EDSL][AP_EVAL] Function: 'malloc'
[EDSL][AP_EVAL] ✓ AP 1 MATCHED call event (simplified)
[EDSL][AP_EVAL] ✗ AP 2 did not match call event

[EDSL][SPOT] ===== SPOT EVALUATION START =====
[EDSL][SPOT] Event: type=0, fn=malloc, sym=x
[EDSL][SPOT] Current automaton state: 0
[EDSL][SPOT] Evaluating 2 APs:
[EDSL][SPOT]   AP ap_1 (node 1) = TRUE [malloc(x) with ReturnValueNonNull]
[EDSL][SPOT]   AP ap_2 (node 2) = FALSE [free(x)]
[EDSL][SPOT] True APs: [ap_1]
[EDSL][SPOT] BDD valuation cube: ap_1 & !ap_2
[EDSL][SPOT] Evaluating transitions from state 0:
[EDSL][SPOT]   Transition 0: cond=ap_1 -> dst=1
[EDSL][SPOT]   ✓ Transition 0 SATISFIED! Moving from state 0 to state 1
[EDSL][SPOT] ===== STATE TRANSITION =====
[EDSL][SPOT] State 0 -> 1
[EDSL][SPOT] ==============================

[EDSL][AP_EVAL] Starting AP evaluation for call event
[EDSL][AP_EVAL] Function: 'free'
[EDSL][AP_EVAL] ✗ AP 1 did not match call event
[EDSL][AP_EVAL] ✓ AP 2 MATCHED call event (simplified)

[EDSL][SPOT] ===== SPOT EVALUATION START =====
[EDSL][SPOT] Event: type=1, fn=free, sym=x
[EDSL][SPOT] Current automaton state: 1
[EDSL][SPOT] Evaluating 2 APs:
[EDSL][SPOT]   AP ap_1 (node 1) = FALSE [malloc(x)]
[EDSL][SPOT]   AP ap_2 (node 2) = TRUE [free(x)]
[EDSL][SPOT] True APs: [ap_2]
[EDSL][SPOT] BDD valuation cube: !ap_1 & ap_2
[EDSL][SPOT] Evaluating transitions from state 1:
[EDSL][SPOT]   Transition 0: cond=ap_2 -> dst=2
[EDSL][SPOT]   ✓ Transition 0 SATISFIED! Moving from state 1 to state 2
[EDSL][SPOT] ===== STATE TRANSITION =====
[EDSL][SPOT] State 1 -> 2
[EDSL][SPOT] ==============================
```

## Test Case
```c
void TEST_OK() {
  void *x = malloc(4);
  if (x) {
    free(x);
  }
}
```

## Success Criteria
- No temporal violations reported
- Correct state transitions: 0 → 1 → 2
- Symbol tracking: added on malloc (non-null branch), removed on free
- Final state: 2 (accepting state)
