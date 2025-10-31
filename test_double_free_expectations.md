# TEST_DOUBLE_FREE Case Expectations - Double-Free Detection

## Test Case
```c
void double_free() {
  void *p = malloc(8);
  if (p) {
    free(p);
    free(p);  // expected-warning{{resource destroyed twice (violates exactly-once) (internal symbol: sym_2)}}
  }
}
```

## Expected Behavior
This test case should **detect a double-free violation** because:
1. `malloc(8)` allocates memory and assigns it to `p`
2. The `if (p)` condition ensures `p` is non-null (state splitting occurs)
3. On the non-null branch, `free(p)` is called the first time (correct)
4. `free(p)` is called a second time (violation!)
5. The second free call should trigger double-free detection

## LTL Formula
```
G( malloc(x non null) → F free(x) ∧ G( free(x) → G X(¬free(x)) ) )
```

**Translation**: "Globally, if malloc(x) with non-null constraint, then eventually free(x), and globally, if free(x) then globally next not free(x)"

The `G X(¬free(x))` part specifically prevents double-free by ensuring that after a free, no more free calls occur.

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

### 3. **Double-Free Detection Logic**
- **Symbol State Tracking**: Each symbol has a state (`Active`, `Inactive`, `Uninitialized`)
- **First Free**: Symbol state changes from `Active` to `Inactive`
- **Second Free**: Detects `Inactive` state and triggers double-free error

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

### 2. **First free call** (PreCall event)
```
[EDSL][AP_EVAL] Starting AP evaluation for call event
[EDSL][AP_EVAL] Function: 'free'
[EDSL][AP_EVAL] ✗ AP 1 did not match call event
[EDSL][AP_EVAL] ✓ AP 2 MATCHED call event

[EDSL][HANDLE] Set symbol to Inactive and removed from tracked set (freed): x

[EDSL][SPOT] ===== SPOT EVALUATION START =====
[EDSL][SPOT] Event: type=1, fn=free, sym=x
[EDSL][SPOT] Current automaton state: 1
[EDSL][SPOT] Evaluating 3 APs:
[EDSL][SPOT]   AP ap_1 (node 1) = TRUE [malloc(x)]
[EDSL][SPOT]   AP ap_2 (node 2) = TRUE [free(x)]
[EDSL][SPOT]   AP ap_END (node -1) = FALSE [<synthetic>]
[EDSL][SPOT] True APs: [ap_1, ap_2]
[EDSL][SPOT] BDD valuation cube: ap_1 & ap_2 & !ap_END
[EDSL][SPOT] Evaluating transitions from state 1:
[EDSL][SPOT]   ✓ Transition 0 SATISFIED! Moving from state 1 to state 2
[EDSL][SPOT] ===== STATE TRANSITION =====
[EDSL][SPOT] State 1 -> 2
[EDSL][SPOT] ==============================
```

**Key Points**:
- Symbol state is set to `Inactive` before removing from tracked set
- Automaton transitions from state 1 to state 2 (obligation fulfilled)
- This is the correct behavior for the first free

### 3. **Second free call** (PreCall event) - **DOUBLE-FREE DETECTION**
```
[EDSL][AP_EVAL] Starting AP evaluation for call event
[EDSL][AP_EVAL] Function: 'free'
[EDSL][AP_EVAL] ✗ AP 1 did not match call event
[EDSL][AP_EVAL] ✓ AP 2 MATCHED call event

[EDSL][HANDLE] Double-free detected for symbol: x
[EDSL][HANDLE] Set symbol to Inactive and removed from tracked set (freed): x
```

**Key Points**:
- **Double-free detection triggers** because symbol is already `Inactive`
- Error node is generated and bug report is emitted immediately
- Function returns early (no further processing)

### 4. **Warning Generation**
```
/Users/efulop/llvm-project/clang/test/Analysis/embedded-dsl-monitor-malloc-free.c:34:3: warning: resource destroyed twice (violates exactly-once) (internal symbol: sym_2) [alpha.dsl.EmbeddedDSLMonitor]
   34 |   free(p); // expected-warning{{resource destroyed twice (violates exactly-once) (internal symbol: sym_2)}}
      |   ^~~~~~~
1 warning generated.
```

## Why This Works

### 1. **Symbol State Management**
- **First Free**: Symbol state changes from `Active` to `Inactive`
- **Second Free**: Detects `Inactive` state and triggers error
- **State Persistence**: Symbol state is stored in GDM (Generic Data Map)

### 2. **Double-Free Detection Logic**
```cpp
// Check for double-free before removing from tracked set
const ::SymbolState *CurPtr = dsl::getSymbolState(MainState, event.Symbol);
if (CurPtr && *CurPtr == ::SymbolState::Inactive) {
  // Double-free detected - create error node and return early
  ExplodedNode *ErrorNode = C.generateErrorNode(MainState);
  if (ErrorNode) {
    static const BugType BT{ContainingChecker, "temporal_violation", "EmbeddedDSLMonitor"};
    std::string msg = "resource destroyed twice (violates exactly-once)";
    // ... create and emit bug report
  }
  return; // Early return prevents further processing
}
```

### 3. **Temporal Logic Enforcement**
- The LTL formula `G( free(x) → G X(¬free(x)) )` ensures no double-free
- State 2 is reached after first free (obligation fulfilled)
- Second free violates the temporal property

### 4. **Immediate Error Reporting**
- Double-free detection happens in `handleEvent` before SPOT stepping
- Error is reported immediately when detected
- No need to wait for end-of-function analysis

## Success Criteria

1. **Double-Free Detection**: Second free call should trigger error
2. **Correct Warning**: "resource destroyed twice (violates exactly-once)"
3. **Proper Location**: Warning should point to the second free call
4. **Symbol Information**: Should include internal symbol ID
5. **Early Detection**: Error should be detected immediately, not at function end

## Key Technical Details

### Symbol State Transitions
```
malloc → Active (tracked)
free   → Inactive (not tracked)
free   → ERROR (double-free detected)
```

### Double-Free Detection Flow
1. **PreCall Event**: `free` function is about to be called
2. **State Check**: Check if symbol is already `Inactive`
3. **Error Generation**: If `Inactive`, generate error node and bug report
4. **Early Return**: Stop processing to prevent further issues

### Error Reporting
- **BugType**: `temporal_violation` with category `EmbeddedDSLMonitor`
- **Message**: "resource destroyed twice (violates exactly-once)"
- **Location**: Points to the second free call
- **Symbol**: Includes internal symbol ID for debugging

## Comparison with Other Cases

| Aspect | TEST_OK | TEST_DOUBLE_FREE | TEST_LEAK_MISSING_FREE |
|--------|---------|------------------|------------------------|
| **First free** | ✅ Correct | ✅ Correct | ❌ Missing |
| **Second free** | N/A | ❌ **Double-free** | N/A |
| **Detection** | No warning | **Double-free warning** | Leak warning |
| **State after first free** | 2 (fulfilled) | 2 (fulfilled) | 1 (waiting) |
| **Error timing** | N/A | **Immediate** | End of function |

This test case validates that the system correctly detects and reports double-free violations, which is crucial for memory safety.
