# Complete Implementation Design: Negated Automaton with Formula-Based Diagnostics

## Overview

This document describes how to implement violation detection using:
1. **Negated automaton** for violation detection (standard model checking)
2. **Original formula structure** for diagnostic message extraction
3. **AP-to-formula-node mapping** for precise violation identification

## Current Implementation Analysis

Based on the current code, the implementation uses:
- LTLf finite semantics with `spot::to_finite()`
- Non-accepting states to detect violations
- Hard-coded diagnostic extraction based on event types

## Proposed Implementation Changes

### 1. Build Negated TGBA Automaton

**File**: `EmbeddedDSLSpot.cpp`, function `buildSpotMonitorFromDSL`

**Current code**:
```cpp
// Convert LTL to LTLf for finite semantics
spot::formula ltlFormula = spot::parse_infix_psl(infix).f;
spot::formula ltlfFormula = spot::from_ltlf(ltlFormula);
spot::translator trans;
trans.set_type(spot::postprocessor::Buchi);
trans.set_pref(spot::postprocessor::Deterministic | spot::postprocessor::SBAcc);
spot::twa_graph_ptr buchiAut = trans.run(ltlfFormula);
R.Monitor = spot::to_finite(buchiAut);
```

**Proposed code**:
```cpp
// Build original formula for diagnostic extraction
spot::formula originalFormula = spot::parse_infix_psl(infix).f;

// Build negated formula for violation detection (standard model checking)
spot::formula negatedFormula = spot::formula::Not(originalFormula);

// Build TGBA automaton for negated formula
spot::translator trans;
trans.set_type(spot::postprocessor::TGBA);
trans.set_pref(spot::postprocessor::Deterministic);
spot::twa_graph_ptr negatedAut = trans.run(negatedFormula);

R.Monitor = negatedAut;
R.OriginalFormula = originalFormula;  // Store for diagnostics
```

### 2. Update Violation Detection Logic

**File**: `EmbeddedDSLSpot.cpp`, function `SpotStepper::step`

**Current logic** (non-accepting = violation):
```cpp
if (!isStateAccepting(Graph, CurrentState)) {
    isViolation = true;
}
```

**Proposed logic** (accepting = violation):
```cpp
if (isStateAccepting(Graph, CurrentState)) {
    isViolation = true;
}
```

### 3. Implement Formula-Based Diagnostic Extraction

**New function** in `EmbeddedDSLSpot.cpp`:

```cpp
std::string analyzeViolationFromOriginalFormula(
    const LTLFormulaBuilder &originalFormulaBuilder,
    const GenericEvent &event,
    int fromState, int toState,
    const std::set<std::string> &trueAPs,
    const std::map<std::string, int> &APToNodeID) {
    
    // Step 1: Determine violation type from event
    ViolationType violationType;
    if (event.Type == EventType::DeadSymbols || 
        event.Type == EventType::EndAnalysis) {
        violationType = ViolationType::LEAK;
    } else if (event.FunctionName == "free") {
        violationType = ViolationType::DOUBLE_FREE;
    } else {
        violationType = ViolationType::UNKNOWN;
    }
    
    // Step 2: Map true APs to original formula node IDs
    std::set<int> involvedNodeIDs;
    for (const auto &ap : trueAPs) {
        auto it = APToNodeID.find(ap);
        if (it != APToNodeID.end()) {
            involvedNodeIDs.insert(it->second);
        }
    }
    
    // Step 3: Find violated subformula based on violation type
    const LTLFormulaNode *root = originalFormulaBuilder.getRootNode();
    const LTLFormulaNode *violatedNode = nullptr;
    
    if (violationType == ViolationType::LEAK) {
        // Leak: Eventually(F) was not satisfied
        violatedNode = findNodeByType(root, LTLNodeType::Eventually);
    } else if (violationType == ViolationType::DOUBLE_FREE) {
        // Double-free: Implies constraint was violated
        violatedNode = findNodeByType(root, LTLNodeType::Implies);
    }
    
    // Step 4: Extract diagnostic from violated node
    if (violatedNode && !violatedNode->DiagnosticLabel.empty()) {
        return violatedNode->DiagnosticLabel;
    }
    
    // Fallback
    return "temporal property violation";
}
```

### 4. Build AP-to-Node-ID Mapping

**New function** in `EmbeddedDSLSpot.cpp`:

```cpp
std::map<std::string, int> buildAPToNodeIDMapping(
    const LTLFormulaBuilder &formulaBuilder) {
    
    std::map<std::string, int> mapping;
    const LTLFormulaNode *root = formulaBuilder.getRootNode();
    
    // Traverse formula tree and build AP -> NodeID mapping
    std::function<void(const LTLFormulaNode*)> traverse = 
        [&](const LTLFormulaNode *node) {
        if (!node) return;
        
        // If this is an atomic node (Call), map its AP
        if (node->Type == LTLNodeType::Atomic) {
            // AP name is typically "ap_N" where N is the node ID
            std::string apName = "ap_" + std::to_string(node->NodeID);
            mapping[apName] = node->NodeID;
        }
        
        // Recursively traverse children
        for (const auto &child : node->Children) {
            traverse(child.get());
        }
    };
    
    traverse(root);
    return mapping;
}
```

## Expected Automaton Structure

For the malloc-free property: `G(ap_1 -> (F(ap_2) & G((ap_2 -> X(G(!(ap_2)))))))`

**Negated TGBA Automaton**:
```
States: 4
Accepting states: [0, 3]
Transitions:
  State 0 (accepting: yes): -> 0 -> 2
  State 1 (accepting: no): -> 0 -> 1 -> 2
  State 2 (accepting: no): -> 2 -> 3
  State 3 (accepting: yes): -> 3
```

**State Semantics**:
- **State 0 (accepting)**: Initial violation state
- **State 1 (non-accepting)**: After malloc, waiting for free
- **State 2 (non-accepting)**: Waiting for free
- **State 3 (accepting)**: Double-free violation

## Violation Detection Strategy

### TEST_OK (Correct Usage)
**Execution**: malloc → free → end
**States**: 0 → 1 → 2 → 3 (non-accepting) → end
**Result**: ✅ No violation (ends in non-accepting state)

### TEST_DOUBLE_FREE
**Execution**: malloc → free → free
**States**: 0 → 1 → 2 → 3 (accepting)
**Result**: ❌ Violation detected at state 3
**Diagnostic**: From `Implies` node: "resource destroyed twice (violates exactly-once)"

### TEST_LEAK_MISSING_FREE
**Execution**: malloc → end
**States**: 0 → 1 (non-accepting) → end in state 1
**Result**: ❌ Violation detected at end (should reach accepting state but didn't)
**Wait**: Actually with negated automaton, we need to check if we're NOT in accepting state at end!

## Important Insight: End-of-Analysis Detection

With negated automaton:
- **Accepting state at end** = violation detected
- **Non-accepting state at end** = property satisfied

For leak detection, we need to check if the automaton is in a **non-accepting state** at the end of analysis, which means the property was violated (resource not freed).

## Revised Violation Detection Logic

```cpp
if (event.Type == EventType::DeadSymbols || event.Type == EventType::EndAnalysis) {
    // End of analysis - check if we're in NON-accepting state (leak)
    // With negated automaton: non-accepting at end = property violated
    if (!isStateAccepting(Graph, CurrentState)) {
        isViolation = true;
        violationType = ViolationType::LEAK;
    }
} else if (event.Type == EventType::PreCall || event.Type == EventType::PostCall) {
    // Function call - check if we reached accepting state (violation)
    if (isStateAccepting(Graph, CurrentState)) {
        isViolation = true;
        violationType = ViolationType::DOUBLE_FREE;
    }
}
```

## Summary

The key insight is that with a negated automaton:
1. **Reaching accepting state during execution** = immediate violation (e.g., double-free)
2. **Ending in non-accepting state** = property violated (e.g., leak)
3. **Diagnostic extraction** comes from original formula structure, not automaton states

This approach combines:
- ✅ Standard model checking practice (negated automaton)
- ✅ Formula-based diagnostics (from original formula)
- ✅ Precise violation identification (AP-to-node mapping)
- ✅ Maintainable implementation (no hard-coded messages)

