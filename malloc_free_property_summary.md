# Malloc-Free Property Detection - Complete Test Case Summary

## Overview
This document summarizes the expectations and detection mechanisms for the three test cases of the malloc-free property using the Embedded DSL Framework with SPOT temporal logic.

## LTL Formula
```
G( malloc(x non null) → F free(x) ∧ G( free(x) → G X(¬free(x)) ) )
```

**Translation**: "Globally, if malloc(x) with non-null constraint, then eventually free(x), and globally, if free(x) then globally next not free(x)"

## Test Cases Summary

| Test Case | Expected Behavior | Key Detection | Warning Location |
|-----------|------------------|---------------|------------------|
| **TEST_OK** | ✅ No warning | Correct malloc/free pattern | N/A |
| **TEST_DOUBLE_FREE** | ⚠️ Double-free warning | Second free call detected | Second free call |
| **TEST_LEAK_MISSING_FREE** | ⚠️ Leak warning | Missing free detected | Return statement |

## Detection Architecture

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

## Detection Mechanisms

### 1. **State Splitting**
- **Trigger**: `ReturnValueNonNull` binding type
- **Purpose**: Handle null vs non-null branches separately
- **Non-null branch**: Tracks symbol and continues analysis
- **Null branch**: Doesn't track symbol (prevents false positives)

### 2. **Symbol Tracking**
- **GDM Storage**: Symbols stored in Generic Data Map
- **State Management**: `Active`, `Inactive`, `Uninitialized`
- **Lifecycle**: Added on malloc (non-null), removed on free

### 3. **Double-Free Detection**
- **Location**: `DSLMonitor::handleEvent` (PreCall events)
- **Logic**: Check if symbol is already `Inactive`
- **Response**: Immediate error generation and early return
- **Timing**: Before SPOT stepping

### 4. **Leak Detection**
- **Location**: `checkDeadSymbols` and `checkEndFunction`
- **Logic**: Check for remaining tracked symbols
- **Response**: Deferred reporting at function end
- **Timing**: End of function analysis

## Detailed Test Case Analysis

### TEST_OK - Correct Pattern
```c
void ok_exactly_once() {
  void *p = malloc(16);
  if (!p)
    return;
  free(p);
}
```

**Flow**:
1. **malloc**: State 0 → 1, symbol tracked (non-null branch)
2. **free**: State 1 → 2, symbol removed
3. **End**: No tracked symbols, no warnings

**Key Points**:
- State splitting prevents false positives on null branch
- Symbol tracking only on non-null branch
- Proper cleanup on free

### TEST_DOUBLE_FREE - Double-Free Violation
```c
void double_free() {
  void *p = malloc(8);
  if (p) {
    free(p);
    free(p);  // Double-free!
  }
}
```

**Flow**:
1. **malloc**: State 0 → 1, symbol tracked (non-null branch)
2. **First free**: State 1 → 2, symbol set to `Inactive`
3. **Second free**: **DOUBLE-FREE DETECTED**, immediate error
4. **End**: Error already reported

**Key Points**:
- Symbol state tracking enables double-free detection
- Immediate error reporting prevents further issues
- Early return stops processing

### TEST_LEAK_MISSING_FREE - Memory Leak
```c
void leak_missing_free() {
  void *p = malloc(32);
  return;  // Missing free!
}
```

**Flow**:
1. **malloc**: State 0 → 1, symbol tracked (non-null branch)
2. **End**: Symbol still tracked, leak detected
3. **Warning**: Deferred report emitted

**Key Points**:
- No free call means symbol remains tracked
- Leak detection at function end
- Deferred reporting when `CheckerContext` available

## Technical Implementation Details

### 1. **AP Evaluation**
```cpp
// Non-null binding types
if (isNonNullBinding(bt)) {
  if (E.Symbol && E.SymbolName == sym) {
    return true;  // Symbol exists and matches
  }
  return false;
}
```

### 2. **State Splitting**
```cpp
if (needsSplit) {
  SVal NE = SVB.evalBinOp(Base, BO_NE, SymV, Null, C.getASTContext().BoolTy);
  if (auto D = NE.getAs<DefinedSVal>()) {
    ProgramStateRef STrue, SFalse;
    std::tie(STrue, SFalse) = C.getConstraintManager().assumeDual(Base, *D);
    // Handle null and non-null branches
  }
}
```

### 3. **Double-Free Detection**
```cpp
const ::SymbolState *CurPtr = dsl::getSymbolState(MainState, event.Symbol);
if (CurPtr && *CurPtr == ::SymbolState::Inactive) {
  // Double-free detected - create error node and return early
  ExplodedNode *ErrorNode = C.generateErrorNode(MainState);
  // ... emit bug report
  return;
}
```

### 4. **Leak Detection**
```cpp
void DSLMonitor::emitDeferredLeakReports(CheckerContext &C) {
  for (const auto &report : DeferredLeakReports) {
    static const BugType BT{Owner, report.BugTypeName, report.BugTypeCategory};
    ExplodedNode *ErrorNode = C.generateErrorNode();
    auto BR = std::make_unique<PathSensitiveBugReport>(BT, report.Message, ErrorNode);
    C.emitReport(std::move(BR));
  }
}
```

## Success Metrics

### 1. **TEST_OK Success Criteria**
- ✅ No warnings generated
- ✅ Correct state transitions: 0 → 1 → 2
- ✅ Symbol properly tracked and cleaned up
- ✅ No false positives

### 2. **TEST_DOUBLE_FREE Success Criteria**
- ✅ Double-free detected immediately
- ✅ Correct warning message
- ✅ Warning points to second free call
- ✅ Early return prevents further processing

### 3. **TEST_LEAK_MISSING_FREE Success Criteria**
- ✅ Leak detected at function end
- ✅ Correct warning message
- ✅ Warning points to return statement
- ✅ Symbol tracking works correctly

## Key Innovations

### 1. **IsNonNull as BindingType Flag**
- **Before**: Separate `IsNonNull` formula element
- **After**: `ReturnValueNonNull` binding type flag
- **Benefit**: Simpler architecture, cleaner code

### 2. **Proper ASTMatcher Evaluation**
- **Implementation**: `clang::ast_matchers::match` function
- **Benefit**: Correct AP matching for function calls
- **Result**: Reliable event detection

### 3. **Deferred Error Reporting**
- **Problem**: `checkDeadSymbols` lacks `CheckerContext`
- **Solution**: Store reports, emit at function end
- **Benefit**: Proper error node creation

### 4. **Immediate Double-Free Detection**
- **Location**: `handleEvent` before SPOT stepping
- **Benefit**: Fast detection, prevents further issues
- **Result**: Better user experience

## Conclusion

The malloc-free property detection system successfully handles all three test cases:

1. **Correct Pattern**: No false positives, proper state management
2. **Double-Free**: Immediate detection and reporting
3. **Memory Leak**: End-of-function detection with deferred reporting

The system demonstrates robust temporal logic evaluation, proper symbol tracking, and effective error reporting, making it suitable for real-world memory safety analysis.
