# Automaton Generation Approaches: Feasibility Analysis for Malloc-Free Property

## Executive Summary

This document analyzes three different automaton generation approaches for detecting violations in the malloc-free property: `G(ap_1 -> (F(ap_2) & G((ap_2 -> X(G(!(ap_2)))))))`. The analysis evaluates the feasibility of detecting all three test cases:

1. **TEST_OK**: Correct malloc-free sequence (should be clean)
2. **TEST_DOUBLE_FREE**: Double-free violation (should show warning)
3. **TEST_LEAK_MISSING_FREE**: Leak violation (should show warning)

## Formula Analysis

**Original LTL Formula**: `G(ap_1 -> (F(ap_2) & G((ap_2 -> X(G(!(ap_2)))))))`

This formula encodes:
- `ap_1`: malloc(x) event (non-null return value)
- `ap_2`: free(x) event
- **Globally**: If malloc(x) occurs, then:
  - **Eventually**: free(x) must occur (F(ap_2))
  - **Globally**: If free(x) occurs, then **Next** **Globally** no more free(x) should occur (G((ap_2 -> X(G(!(ap_2))))))

## Automaton Generation Approaches

### 1. Monitor (Safety) Approach
```
States: 3
Accepting states: [0, 1, 2] (ALL states are accepting)
Transitions:
  State 0 (accepting: yes): -> 0
  State 1 (accepting: yes): -> 0 -> 1  
  State 2 (accepting: yes): -> 0 -> 1 -> 2
```

**Analysis**:
- ✅ **All states are accepting** - this is a safety property
- ❌ **Cannot detect violations** - safety properties only accept valid traces
- ❌ **Not suitable for error detection** - we need non-accepting states to detect violations

### 2. TGBA (Infinite) Approach
```
States: 3
Accepting states: [1, 2] (states 1 and 2 are accepting)
Transitions:
  State 0 (accepting: no): -> 0 -> 2
  State 1 (accepting: yes): -> 0 -> 1 -> 2
  State 2 (accepting: yes): -> 2
```

**Analysis**:
- ✅ **Has non-accepting states** (state 0) - can detect violations
- ✅ **State 0**: Initial state, non-accepting (can detect leaks)
- ✅ **State 1**: After malloc, accepting (can detect double-free)
- ✅ **State 2**: After free, accepting (can detect double-free)
- ✅ **Suitable for error detection** - has both accepting and non-accepting states

### 3. LTLf Finite Semantics Approach
```
States: 4
Accepting states: [0, 3] (states 0 and 3 are accepting)
Transitions:
  State 0 (accepting: yes): -> 0 -> 2 -> 3
  State 1 (accepting: no): -> 0 -> 2 -> 3
  State 2 (accepting: no): -> 2 -> 3
  State 3 (accepting: yes): -> 3
```

**Analysis**:
- ✅ **Has non-accepting states** (states 1, 2) - can detect violations
- ✅ **State 0**: Initial state, accepting (valid starting state)
- ✅ **State 2**: After malloc, non-accepting (can detect leaks)
- ✅ **State 3**: After free, accepting (can detect double-free)
- ✅ **Suitable for error detection** - has both accepting and non-accepting states

## Test Case Feasibility Analysis

### TEST_OK (Correct malloc-free sequence)
**Expected**: No warnings
**Required**: Automaton should reach accepting state after free

| Approach | Feasible | Strategy |
|----------|----------|----------|
| Monitor | ❌ | All states accepting, cannot detect violations |
| TGBA | ✅ | State 0 → State 2 → State 2 (accepting) |
| LTLf | ✅ | State 0 → State 2 → State 3 (accepting) |

### TEST_DOUBLE_FREE (Double-free violation)
**Expected**: Warning on second free call
**Required**: Automaton should detect when trying to free from accepting state

| Approach | Feasible | Strategy |
|----------|----------|----------|
| Monitor | ❌ | All states accepting, cannot detect violations |
| TGBA | ✅ | State 2 (accepting) → State 2 (accepting) - detect double-free |
| LTLf | ✅ | State 3 (accepting) → State 3 (accepting) - detect double-free |

### TEST_LEAK_MISSING_FREE (Leak violation)
**Expected**: Warning at end of analysis
**Required**: Automaton should be in non-accepting state at end

| Approach | Feasible | Strategy |
|----------|----------|----------|
| Monitor | ❌ | All states accepting, cannot detect violations |
| TGBA | ✅ | State 0 (non-accepting) - detect leak |
| LTLf | ✅ | State 2 (non-accepting) - detect leak |

## Recommended Approach: TGBA (Infinite)

### Why TGBA is the Best Choice

1. **Simplest Structure**: Only 3 states, easy to understand and debug
2. **Clear State Semantics**:
   - State 0: Initial state (non-accepting) - detects leaks
   - State 1: After malloc (accepting) - detects double-free
   - State 2: After free (accepting) - detects double-free
3. **Efficient**: Fewer states mean faster evaluation
4. **Proven**: Standard approach for LTL model checking

### Implementation Strategy

1. **Leak Detection**: Check if automaton is in non-accepting state (state 0) at end of analysis
2. **Double-Free Detection**: Check if trying to free from accepting state (state 1 or 2)
3. **Correct Usage**: Automaton transitions from state 0 → state 1 → state 2 (all accepting)

### State Transition Logic

```
Initial: State 0 (non-accepting)
malloc(x): State 0 → State 1 (accepting)
free(x): State 1 → State 2 (accepting)
free(x) again: State 2 → State 2 (accepting) - DETECT DOUBLE-FREE
End without free: State 0 (non-accepting) - DETECT LEAK
```

## Conclusion

**The TGBA (Infinite) approach is the most suitable for detecting all three test cases** because:

1. ✅ It has both accepting and non-accepting states
2. ✅ It can detect leaks (non-accepting state at end)
3. ✅ It can detect double-frees (trying to free from accepting state)
4. ✅ It has the simplest structure (3 states)
5. ✅ It's the standard approach for LTL model checking

The current LTLf approach is also feasible but more complex (4 states) and may be overkill for this simple property. The Monitor approach is not suitable as it cannot detect violations.

## Recommendation

**Switch from LTLf to TGBA approach** for the malloc-free property checker. This will provide:
- Simpler implementation
- Better performance
- Clearer semantics
- Proven reliability
