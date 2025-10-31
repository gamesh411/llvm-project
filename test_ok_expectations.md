# TEST_OK Case Expectations - Correct malloc/free Pattern

## Test Case
```c
void ok_exactly_once() {
  void *p = malloc(16);
  if (!p)
    return;
  free(p);
}
```

## Expected Behavior
This test case should **NOT generate any warnings** because:
1. `malloc(16)` allocates memory and assigns it to `p`
2. The `if (!p)` condition triggers state splitting (null vs non-null branches)
3. On the non-null branch, `free(p)` is called exactly once
4. The memory is properly freed, satisfying the temporal property
5. No temporal violations should be detected

## LTL Formula
```
G( malloc(x non null) → F free(x) ∧ G( free(x) → G X(¬free(x)) ) )
```

**Translation**: "Globally, if malloc(x) with non-null constraint, then eventually free(x), and globally, if free(x) then globally next not free(x)"

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

### 3. **State Transitions**
- **0 → 1**: When `ap_1` (malloc) is TRUE
- **1 → 2**: When `ap_2` (free) is TRUE
- **2 → 2**: Stay in accepting state

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

### 2. **free call** (PreCall event)
```
[EDSL][AP_EVAL] Starting AP evaluation for call event
[EDSL][AP_EVAL] Function: 'free'
[EDSL][AP_EVAL] ✗ AP 1 did not match call event
[EDSL][AP_EVAL] ✓ AP 2 MATCHED call event

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

[EDSL][HANDLE] Set symbol to Inactive and removed from tracked set (freed): x
```

**Key Points**:
- Both `ap_1` and `ap_2` are TRUE (malloc happened, free happening)
- Automaton transitions from state 1 to state 2 (obligation fulfilled)
- Symbol is removed from tracked set and set to Inactive state

### 3. **End of function** (EndFunction event)
```
[EDSL][DEFERRED] Emitting 0 deferred leak reports
[EDSL][DEFERRED] Clearing 0 deferred leak reports
```

**Key Points**:
- No tracked symbols remain (symbol was removed on free)
- No leak reports are generated
- Function completes successfully

## Why This Works

### 1. **State Splitting Logic**
- The `ReturnValueNonNull` binding type triggers state splitting
- Only the non-null branch tracks the symbol
- The null branch doesn't track anything (no false positive)

### 2. **Symbol Tracking**
- Symbol is added to tracked set only after successful malloc (non-null branch)
- Symbol is removed from tracked set when freed
- No symbols remain tracked at function end

### 3. **Temporal Logic**
- The formula ensures malloc is followed by exactly one free
- The `G X(¬free(x))` part prevents double-free
- State 2 is an accepting state (obligation fulfilled)

### 4. **AP Evaluation**
- `ap_1` (malloc): TRUE when malloc call with matching symbol
- `ap_2` (free): TRUE when free call with matching symbol
- Proper ASTMatcher evaluation ensures correct matching

## Success Criteria

1. **No Warnings**: No temporal violations should be reported
2. **Correct State Transitions**: 0 → 1 → 2
3. **Symbol Management**: Added on malloc (non-null), removed on free
4. **State Splitting**: Only non-null branch tracks the symbol
5. **Final State**: State 2 (accepting state)

## Key Technical Details

### Binding Type System
- `ReturnValueNonNull`: Extracts return value and enforces non-null constraint
- `FirstParameter`: Extracts first parameter (the pointer to free)
- `isNonNullBinding()`: Helper to check if binding type has non-null constraint

### State Splitting
- Triggered by `ReturnValueNonNull` binding type
- Creates separate program states for null and non-null branches
- Only non-null branch continues with symbol tracking

### Double-Free Prevention
- Symbol state is set to `Inactive` before removing from tracked set
- Double-free detection checks for `Inactive` state
- Prevents multiple free calls on the same symbol

This test case validates that the system correctly handles the normal malloc/free pattern without generating false positives.
