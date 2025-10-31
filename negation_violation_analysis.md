# Negation-Based Violation Detection Analysis

## The Model Checking Principle

You're absolutely right! In model checking, the standard approach is to:

1. **Negate the property** we want to verify
2. **Build an automaton** for the negated property
3. **Detect violations** when the automaton reaches an **accepting state**

This is because:
- **Original property**: "The system should always satisfy P"
- **Negated property**: "The system should NOT always satisfy P" (i.e., "There exists a violation of P")
- **Violation detection**: When the negated automaton accepts, we found a violation!

## Negated Formula Analysis

**Original**: `G(ap_1 -> (F(ap_2) & G((ap_2 -> X(G(!(ap_2)))))))`
**Negated**: `!G(ap_1 -> (Fap_2 & G(ap_2 -> XG!ap_2)))`

The negated formula means: "There exists a trace where the malloc-free property is violated"

## Automaton Analysis for Negated Formula

### 1. Monitor (Safety) on NEGATED
```
States: 1
Accepting states: [0] (ALL states accepting)
Transitions:
  State 0 (accepting: yes): -> 0
```

**Analysis**: 
- ❌ **Too simple** - only 1 state, cannot distinguish between different violation types
- ❌ **Not useful** - cannot provide specific violation information

### 2. TGBA (Infinite) on NEGATED
```
States: 4
Accepting states: [0, 3] (states 0 and 3 are accepting)
Transitions:
  State 0 (accepting: yes): -> 0 -> 2
  State 1 (accepting: no): -> 0 -> 1 -> 2
  State 2 (accepting: no): -> 2 -> 3
  State 3 (accepting: yes): -> 3
```

**Analysis**:
- ✅ **Has both accepting and non-accepting states**
- ✅ **State 0 (accepting)**: Can detect violations immediately
- ✅ **State 3 (accepting)**: Can detect violations after some events
- ✅ **States 1, 2 (non-accepting)**: Intermediate states

### 3. LTLf Finite Semantics on NEGATED
```
States: 4
Accepting states: [1, 3] (states 1 and 3 are accepting)
Transitions:
  State 0 (accepting: no): -> 0 -> 1 -> 2
  State 1 (accepting: yes): -> 1 -> 2
  State 2 (accepting: no): -> 2 -> 3
  State 3 (accepting: yes): -> 3
```

**Analysis**:
- ✅ **Has both accepting and non-accepting states**
- ✅ **State 1 (accepting)**: Can detect violations after malloc
- ✅ **State 3 (accepting)**: Can detect violations after free
- ✅ **States 0, 2 (non-accepting)**: Intermediate states

## Violation Detection Strategy

### With Negated Automata

**Violation Detection**: When the automaton reaches an **accepting state**, we have a violation!

### Test Case Analysis

#### TEST_OK (Correct malloc-free sequence)
**Expected**: No violations (automaton should NOT reach accepting state)

| Approach | Feasible | Strategy |
|----------|----------|----------|
| Monitor | ❌ | Too simple, cannot distinguish |
| TGBA | ✅ | Should stay in non-accepting states (1, 2) |
| LTLf | ✅ | Should stay in non-accepting states (0, 2) |

#### TEST_DOUBLE_FREE (Double-free violation)
**Expected**: Violation detected on second free call

| Approach | Feasible | Strategy |
|----------|----------|----------|
| Monitor | ❌ | Too simple, cannot distinguish |
| TGBA | ✅ | Second free should lead to accepting state (0 or 3) |
| LTLf | ✅ | Second free should lead to accepting state (1 or 3) |

#### TEST_LEAK_MISSING_FREE (Leak violation)
**Expected**: Violation detected at end of analysis

| Approach | Feasible | Strategy |
|----------|----------|----------|
| Monitor | ❌ | Too simple, cannot distinguish |
| TGBA | ✅ | End in accepting state (0 or 3) |
| LTLf | ✅ | End in accepting state (1 or 3) |

## Comparison: Original vs Negated Approach

### Original Approach (Current)
- **Property**: "System should satisfy P"
- **Violation**: Non-accepting state
- **Logic**: "If not accepting, then violation"

### Negated Approach (Model Checking Standard)
- **Property**: "System should NOT satisfy P" (violations)
- **Violation**: Accepting state
- **Logic**: "If accepting, then violation"

## Recommendation: Use Negated Approach

### Why Negated Approach is Better

1. **Standard Practice**: This is the established model checking methodology
2. **Clearer Semantics**: Accepting state = violation (intuitive)
3. **Better Tool Support**: Most model checkers work this way
4. **Easier Debugging**: Violations are marked by accepting states

### Implementation Strategy

1. **Build automaton for negated formula**
2. **Detect violations when reaching accepting states**
3. **Use state information to determine violation type**:
   - State 0 (TGBA): Immediate violation (leak)
   - State 3 (TGBA): Violation after free (double-free)
   - State 1 (LTLf): Violation after malloc (leak)
   - State 3 (LTLf): Violation after free (double-free)

## Conclusion

**Yes, you're absolutely correct!** The negation-based approach is the standard practice in model checking and should be used. It provides:

- ✅ **Clearer semantics** (accepting = violation)
- ✅ **Standard methodology** (established practice)
- ✅ **Better tool support** (most model checkers work this way)
- ✅ **Easier implementation** (violation detection is straightforward)

The **TGBA on negated formula** appears to be the best choice with 4 states and clear accepting state semantics for different violation types.
