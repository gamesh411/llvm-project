# Evaluation Analysis: Hypothesis vs. Reality

## ❌ **CRITICAL ISSUES FOUND**

### 1. **Symbol Extraction Problem**
**Expected**: `free` call should extract the symbol from the first parameter
**Reality**: `free` call is extracting `null` symbol
```
[EDSL][CREATE] AP-driven extraction: apId=1 symbolName='x' bindingType=0 Sym=null
[EDSL][CREATE] Creating PostCallEvent with symbol ID=0
[EDSL][POSTCALL] event.Symbol=null event.SymbolName='x'
```

**Root Cause**: The `free` call is using AP 1 (which has `bindingType=0` = ReturnValue) instead of AP 4 (which should have `bindingType=1` = FirstParameter).

### 2. **AP Registration Problem**
**Expected**: 3 APs (malloc, __isnonnull, free)
**Reality**: Only 2 APs registered, but AP 4 is registered multiple times
```
[EDSL][INIT] Registered AP 1 binding: symbol='x' type=0
[EDSL][INIT] Registered AP 2 binding: symbol='x' type=0  // This should be __isnonnull
[EDSL][INIT] Registered AP 4 binding: symbol='x' type=1  // This should be free
[EDSL][INIT] Registered AP 4 binding: symbol='x' type=1  // Duplicate!
[EDSL][INIT] Registered AP 4 binding: symbol='x' type=1  // Duplicate!
```

**Root Cause**: The `__isnonnull` AP (AP 2) is not being registered with a matcher, and AP 4 is being registered multiple times.

### 3. **State Transition Problem**
**Expected**: State 0 → 1 → 2
**Reality**: State 0 → 0 (staying in initial state)
```
[EDSL][SPOT]   ✓ Transition 0 SATISFIED! Moving from state 0 to state 0
[EDSL][SPOT] ===== STATE TRANSITION =====
[EDSL][SPOT] State 0 -> 0
```

**Root Cause**: The automaton is not transitioning to state 1 because the condition `ap_1 & ap_2` is not being satisfied properly.

### 4. **Leak Detection Problem**
**Expected**: No leak (TEST_OK case)
**Reality**: False positive leak detected
```
[EDSL][LEAK] Detected leak for sym_id=2 - deferring report
[EDSL][DEFERRED] Emitted leak report: resource not destroyed (violates exactly-once)
```

**Root Cause**: The `free` call is not properly removing the symbol from tracking because it's not extracting the correct symbol.

## 🔍 **DETAILED ANALYSIS**

### AP Registration Issues
1. **AP 2 (__isnonnull)**: Registered but no matcher, so it never matches
2. **AP 4 (free)**: Registered multiple times, causing confusion
3. **AP 1 (malloc)**: Correctly registered and matches

### Symbol Extraction Issues
1. **malloc**: Correctly extracts symbol (symbol ID=2)
2. **free**: Incorrectly tries to extract from return value instead of first parameter
3. **Symbol tracking**: Symbol is added but never removed because free doesn't extract the right symbol

### Automaton Issues
1. **Formula**: The generated formula is more complex than expected due to sentinel APs
2. **Transitions**: The automaton has 3 states but transitions are not working as expected
3. **AP Evaluation**: `ap_2` (__isnonnull) is always FALSE because it never matches

## 🛠️ **REQUIRED FIXES**

### 1. Fix AP Registration
- Ensure `__isnonnull` AP gets a proper matcher
- Prevent duplicate AP registrations
- Ensure `free` AP uses `FirstParameter` binding

### 2. Fix Symbol Extraction
- Ensure `free` calls extract symbol from first parameter, not return value
- Fix the AP selection logic in event creation

### 3. Fix State Transitions
- Debug why `ap_2` (__isnonnull) is not evaluating to TRUE
- Ensure proper state transitions in the automaton

### 4. Fix Leak Detection
- Ensure symbols are properly removed from tracking when freed
- Fix the symbol extraction for free calls

## 📊 **COMPARISON SUMMARY**

| Aspect | Expected | Reality | Status |
|--------|----------|---------|--------|
| AP Registration | 3 APs (malloc, __isnonnull, free) | 2 APs + duplicates | ❌ |
| Symbol Extraction (malloc) | Valid symbol | Valid symbol (ID=2) | ✅ |
| Symbol Extraction (free) | Valid symbol from param | null (wrong AP) | ❌ |
| State Transitions | 0→1→2 | 0→0 | ❌ |
| Leak Detection | No leak | False positive | ❌ |
| AP Evaluation | ap_2=TRUE | ap_2=FALSE | ❌ |

## 🎯 **NEXT STEPS**

1. **Fix AP registration** to ensure all 3 APs are properly registered with correct bindings
2. **Fix symbol extraction** for free calls to use the correct AP (FirstParameter)
3. **Debug AP evaluation** to understand why __isnonnull is not working
4. **Test again** to verify the fixes work correctly

The core issue is that the AP-driven event creation system is not working correctly - it's not properly distinguishing between different function calls and their binding types.
