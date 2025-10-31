# Expectations for leak_missing_free Test Case

## Test Case
```c
void leak_missing_free() {
  void *p = malloc(4);
  if (p) {
    // Missing free(p) - this should be detected as a leak
  }
}
```

## Expected Behavior
This test case should **detect a memory leak** because:
1. `malloc(4)` allocates memory and assigns it to `p`
2. The `if (p)` condition ensures `p` is non-null (state splitting occurs)
3. On the non-null branch, the memory is never freed
4. When the function ends, the tracked symbol should still be active
5. This should trigger a leak detection in `checkDeadSymbols` or `checkEndFunction`

## Expected Evaluation Order

### 1. **malloc call** (PostCall event)
- **AP Evaluation**:
  - `ap_1` (malloc(x) with ReturnValueNonNull) = TRUE
  - `ap_2` (free(x)) = FALSE
- **State Transition**: 0 → 1 (waiting for free)
- **Symbol Tracking**: Add symbol to tracked set on non-null branch only
- **State Splitting**: Yes, because binding type is `ReturnValueNonNull`

### 2. **End of function** (EndFunction event)
- **AP Evaluation**:
  - `ap_1` (malloc(x)) = FALSE
  - `ap_2` (free(x)) = FALSE
- **State Transition**: Stay in state 1 (waiting for free)
- **Leak Detection**: Symbol is still tracked and active → **LEAK DETECTED**

## Expected Trace Output

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

[EDSL][LEAK] Detected leak for sym_id=X - deferring report
[EDSL][DEFERRED] Adding deferred leak report: resource not destroyed (violates exactly-once)
[EDSL][DEFERRED] Emitted leak report: resource not destroyed (violates exactly-once)
```

## Key Differences from TEST_OK

| Aspect | TEST_OK | leak_missing_free |
|--------|---------|-------------------|
| **free call** | ✅ Present | ❌ Missing |
| **State after malloc** | 0 → 1 | 0 → 1 |
| **State after free** | 1 → 2 | N/A (no free) |
| **Final state** | 2 (accepting) | 1 (waiting for free) |
| **Leak detection** | ❌ No leak | ✅ Leak detected |
| **Expected result** | No warning | Warning generated |

## Success Criteria

1. **Leak Detection**: The system should detect that the allocated memory is never freed
2. **Correct State**: The automaton should remain in state 1 (waiting for free)
3. **Symbol Tracking**: The symbol should remain tracked and active
4. **Warning Generation**: A warning should be generated about the missing free
5. **Proper Location**: The warning should point to the malloc call or the end of function

## Potential Issues to Watch For

1. **AP Evaluation**: Both APs might still be evaluating to FALSE
2. **State Transitions**: Might not transition from state 0 to state 1
3. **Symbol Tracking**: Symbol might not be added to tracked set
4. **Leak Detection**: Might not detect the leak even if symbol is tracked
5. **Warning Location**: Warning might point to wrong location

## Expected Warning Message

```
/Users/efulop/llvm-project/clang/test/Analysis/embedded-dsl-monitor-malloc-free.c:XX:Y: warning: resource not destroyed (violates exactly-once) (internal symbol: sym_X) [alpha.dsl.EmbeddedDSLMonitor]
  XX |   void *p = malloc(4);
     |   ^~~~~~~
```

This test case is crucial because it validates that our system can actually detect real memory leaks, not just avoid false positives.
