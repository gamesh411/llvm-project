# TEST_LEAK_MISSING_FREE Case Expectations - Memory Leak Detection

## Test Case
```c
void leak_missing_free() {
  void *p = malloc(32);
  return;  // expected-warning{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
}
```

## Expected Behavior
This test case should **detect a memory leak** because:
1. `malloc(32)` allocates memory and assigns it to `p`
2. No null check is performed (no state splitting)
3. The allocated memory is never freed
4. When the function ends, the symbol is still tracked and active
5. This should trigger a leak detection in `checkDeadSymbols` or `checkEndFunction`

## LTL Formula
```
G( malloc(x non null) → F free(x) ∧ G( free(x) → G X(¬free(x)) ) )
```

**Translation**: "Globally, if malloc(x) with non-null constraint, then eventually free(x), and globally, if free(x) then globally next not free(x)"

The `F free(x)` part requires that free must eventually happen, which is violated when the function ends without freeing.

## How Detection Works

### 1. **Formula Structure**
- **AP 1**: `malloc(x non null)` - detects malloc calls with non-null constraint
- **AP 2**: `free(x)` - detects free calls
- **Binding Types**: 
  - `malloc`: `ReturnValueNonNull` (type 3)
  - `free`: `FirstParameter` (type 1)

### 2. **Automaton States**
- **State 0**: Initial state (no obligation)
- **State 1**: Waiting for free (after malloc + non-null)
- **State 2**: Obligation fulfilled (after free)

### 3. **Leak Detection Logic**
- **Symbol Tracking**: Symbols are tracked in the GDM (Generic Data Map)
- **End-of-Function**: `checkEndFunction` checks for remaining tracked symbols
- **Deferred Reporting**: Leak reports are collected and emitted at function end

## Expected Evaluation Order

### 1. **malloc call** (PostCall event)
```
[EDSL][AP_EVAL] Starting AP evaluation for call event
[EDSL][AP_EVAL] Function: 'malloc'
[EDSL][AP_EVAL] ✓ AP 1 MATCHED call event
[EDSL][AP_EVAL] ✗ AP 2 did not match call event

[EDSL][SPOT] ===== SPOT EVALUATION START =====
[EDSL][SPOT] Event: type=0, fn=malloc, sym=x
[EDSL][SPOT] Current automaton state: 0
[EDSL][SPOT] Evaluating 3 APs:
[EDSL][SPOT]   AP ap_1 (node 1) = TRUE [malloc(x) with ReturnValueNonNull]
[EDSL][SPOT]   AP ap_2 (node 2) = FALSE [free(x)]
[EDSL][SPOT]   AP ap_END (node -1) = FALSE [<synthetic>]
[EDSL][SPOT] True APs: [ap_1]
[EDSL][SPOT] BDD valuation cube: ap_1 & !ap_2 & !ap_END
[EDSL][SPOT] Evaluating transitions from state 0:
[EDSL][SPOT]   ✓ Transition 0 SATISFIED! Moving from state 0 to state 1
[EDSL][SPOT] ===== STATE TRANSITION =====
[EDSL][SPOT] State 0 -> 1
[EDSL][SPOT] ==============================

[EDSL][HANDLE] Added symbol to tracked set (non-null branch): x
```

**Key Points**:
- State splitting occurs because `ReturnValueNonNull` binding type
- Symbol is added to tracked set only on non-null branch
- Automaton transitions from state 0 to state 1 (waiting for free)

### 2. **End of function** (EndFunction event)
```
[EDSL][TRACE] checkEndFunction node=0x... state=0x...
[EDSL][DEFERRED] Emitting 1 deferred leak reports
[EDSL][DEFERRED] Emitted leak report: resource not destroyed (violates exactly-once)
[EDSL][DEFERRED] Clearing 1 deferred leak reports
```

**Key Points**:
- Function ends without calling free
- Symbol is still tracked and active
- Leak detection triggers deferred report
- Report is emitted immediately

### 3. **Warning Generation**
```
/Users/efulop/llvm-project/clang/test/Analysis/embedded-dsl-monitor-malloc-free.c:26:3: warning: resource not destroyed (violates exactly-once) (internal symbol: sym_2) [alpha.dsl.EmbeddedDSLMonitor]
   26 |   return;  // expected-warning{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
      |   ^~~~~~
1 warning generated.
```

## Why This Works

### 1. **Symbol Tracking**
- Symbol is added to tracked set after successful malloc (non-null branch)
- Symbol remains tracked throughout function execution
- No free call removes the symbol from tracking

### 2. **Leak Detection in checkEndFunction**
```cpp
void EmbeddedDSLMonitorChecker::checkEndFunction(const ReturnStmt *RS, CheckerContext &C) {
  // ... other code ...
  
  // Emit any deferred leak reports
  if (Monitor) {
    Monitor->emitDeferredLeakReports(C);
  }
}
```

### 3. **Deferred Leak Reporting**
- Leak reports are collected during `checkDeadSymbols`
- Reports are stored in `DeferredLeakReports` vector
- Reports are emitted at function end when `CheckerContext` is available

### 4. **Temporal Logic Violation**
- The LTL formula requires `F free(x)` (eventually free)
- When function ends without free, this obligation is violated
- The automaton remains in state 1 (waiting for free) instead of state 2 (fulfilled)

## Expected Trace Output

```
[EDSL][INIT] Registered AP 1 binding: symbol='x' type=3
[EDSL][INIT] Registered AP 1 matcher for event matching
[EDSL][INIT] Registered AP 2 binding: symbol='x' type=1
[EDSL][INIT] Registered AP 2 matcher for event matching

[EDSL][AP_EVAL] Starting AP evaluation for call event
[EDSL][AP_EVAL] Function: 'malloc'
[EDSL][AP_EVAL] ✓ AP 1 MATCHED call event
[EDSL][AP_EVAL] ✗ AP 2 did not match call event

[EDSL][SPOT] ===== SPOT EVALUATION START =====
[EDSL][SPOT] Event: type=0, fn=malloc, sym=x
[EDSL][SPOT] Current automaton state: 0
[EDSL][SPOT] Evaluating 3 APs:
[EDSL][SPOT]   AP ap_1 (node 1) = TRUE [malloc(x) with ReturnValueNonNull]
[EDSL][SPOT]   AP ap_2 (node 2) = FALSE [free(x)]
[EDSL][SPOT]   AP ap_END (node -1) = FALSE [<synthetic>]
[EDSL][SPOT] True APs: [ap_1]
[EDSL][SPOT] BDD valuation cube: ap_1 & !ap_2 & !ap_END
[EDSL][SPOT] Evaluating transitions from state 0:
[EDSL][SPOT]   ✓ Transition 0 SATISFIED! Moving from state 0 to state 1
[EDSL][SPOT] ===== STATE TRANSITION =====
[EDSL][SPOT] State 0 -> 1
[EDSL][SPOT] ==============================

[EDSL][HANDLE] Added symbol to tracked set (non-null branch): x

[EDSL][TRACE] checkDeadSymbols ...
[EDSL][LEAK] Detected leak for sym_id=2 - deferring report

[EDSL][TRACE] checkEndFunction ...
[EDSL][DEFERRED] Emitting 1 deferred leak reports
[EDSL][DEFERRED] Emitted leak report: resource not destroyed (violates exactly-once)
[EDSL][DEFERRED] Clearing 1 deferred leak reports
```

## Success Criteria

1. **Leak Detection**: System should detect that allocated memory is never freed
2. **Correct State**: Automaton should remain in state 1 (waiting for free)
3. **Symbol Tracking**: Symbol should remain tracked and active
4. **Warning Generation**: Warning should be generated about missing free
5. **Proper Location**: Warning should point to the return statement or malloc call

## Key Technical Details

### State Splitting Logic
- **Trigger**: `ReturnValueNonNull` binding type
- **Non-null branch**: Tracks symbol and continues analysis
- **Null branch**: Doesn't track symbol (no false positive)

### Leak Detection Flow
1. **checkDeadSymbols**: Called during analysis to check for dead symbols
2. **Symbol Check**: If symbol is tracked and active, it's a potential leak
3. **Deferred Report**: Leak report is stored for later emission
4. **checkEndFunction**: Emits all deferred leak reports

### Deferred Reporting
- **Why Deferred**: `checkDeadSymbols` doesn't have `CheckerContext`
- **When Emitted**: At function end when `CheckerContext` is available
- **Error Node**: Uses current predecessor for proper error reporting

## Comparison with Other Cases

| Aspect | TEST_OK | TEST_DOUBLE_FREE | TEST_LEAK_MISSING_FREE |
|--------|---------|------------------|------------------------|
| **free call** | ✅ Present | ✅ Present (twice) | ❌ **Missing** |
| **State after malloc** | 0 → 1 | 0 → 1 | 0 → 1 |
| **State after free** | 1 → 2 | 1 → 2 | N/A (no free) |
| **Final state** | 2 (accepting) | 2 (accepting) | 1 (waiting) |
| **Detection** | No warning | Double-free warning | **Leak warning** |
| **Error timing** | N/A | Immediate | End of function |

## Potential Issues to Watch For

1. **AP Evaluation**: Both APs might evaluate to FALSE
2. **State Transitions**: Might not transition from state 0 to state 1
3. **Symbol Tracking**: Symbol might not be added to tracked set
4. **Leak Detection**: Might not detect leak even if symbol is tracked
5. **Warning Location**: Warning might point to wrong location

## Expected Warning Message

```
/Users/efulop/llvm-project/clang/test/Analysis/embedded-dsl-monitor-malloc-free.c:26:3: warning: resource not destroyed (violates exactly-once) (internal symbol: sym_2) [alpha.dsl.EmbeddedDSLMonitor]
   26 |   return;  // expected-warning{{resource not destroyed (violates exactly-once) (internal symbol: sym_2)}}
      |   ^~~~~~
1 warning generated.
```

This test case is crucial because it validates that the system can detect real memory leaks, not just avoid false positives or detect double-frees.
