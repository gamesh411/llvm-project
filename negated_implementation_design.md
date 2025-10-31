# Negated Automaton Implementation Design

## Overview

We want to use the **negated automaton** for violation detection (standard model checking practice) while still extracting diagnostic messages from the **original formula structure**. This requires:

1. **Build negated automaton** for violation detection
2. **Keep original formula** for diagnostic extraction
3. **Map APs to original formula nodes** for precise diagnostics
4. **Use state transitions** to determine violated subformulas

## Implementation Strategy

### 1. Dual Automaton Approach

```cpp
class DSLMonitor {
private:
    spot::twa_graph_ptr NegatedAutomaton;  // For violation detection
    spot::formula OriginalFormula;         // For diagnostic extraction
    LTLFormulaBuilder OriginalFormulaBuilder; // For formula structure analysis
    std::map<std::string, int> APToNodeID; // Map AP names to original formula node IDs
};
```

### 2. Violation Detection Logic

```cpp
// With negated automaton: accepting state = violation
bool isViolation = false;

if (event.Type == EventType::DeadSymbols || event.Type == EventType::EndAnalysis) {
    // End of analysis - check if we're in accepting state (violation)
    if (event.Symbol && UseState && dsl::containsTrackedSymbol(UseState, event.Symbol)) {
        if (isStateAccepting(NegatedAutomaton, CurrentState)) {
            isViolation = true;
        }
    }
} else if (event.Type == EventType::PreCall || event.Type == EventType::PostCall) {
    // Function call - check if we transitioned to accepting state (violation)
    if (event.Symbol && UseState && dsl::containsTrackedSymbol(UseState, event.Symbol)) {
        if (isStateAccepting(NegatedAutomaton, CurrentState)) {
            isViolation = true;
        }
    }
}
```

### 3. Diagnostic Extraction Strategy

The key insight is to use the **state transition** and **AP evaluation** to determine which part of the original formula was violated:

```cpp
std::string analyzeViolationFromOriginalFormula(
    const LTLFormulaBuilder &originalFormula,
    const GenericEvent &event,
    int fromState, int toState,
    const std::set<std::string> &trueAPs) {
    
    // 1. Determine violation type based on state transition
    ViolationType violationType = determineViolationType(fromState, toState, event);
    
    // 2. Map APs to original formula nodes
    std::set<int> violatedNodeIDs = mapAPsToFormulaNodes(trueAPs, APToNodeID);
    
    // 3. Find the smallest violated subformula
    const LTLFormulaNode *violatedNode = findSmallestViolatedSubformula(
        originalFormula.getRootNode(), violatedNodeIDs, violationType);
    
    // 4. Extract diagnostic from violated node
    return violatedNode ? violatedNode->DiagnosticLabel : "temporal property violation";
}
```

### 4. State Transition Analysis

```cpp
enum class ViolationType {
    LEAK,           // End of analysis in accepting state
    DOUBLE_FREE,    // Free call leading to accepting state
    IMMEDIATE       // Immediate violation (e.g., invalid state)
};

ViolationType determineViolationType(int fromState, int toState, const GenericEvent &event) {
    if (event.Type == EventType::DeadSymbols || event.Type == EventType::EndAnalysis) {
        return ViolationType::LEAK;
    } else if (event.FunctionName == "free") {
        return ViolationType::DOUBLE_FREE;
    } else {
        return ViolationType::IMMEDIATE;
    }
}
```

### 5. AP to Formula Node Mapping

```cpp
std::set<int> mapAPsToFormulaNodes(
    const std::set<std::string> &trueAPs,
    const std::map<std::string, int> &APToNodeID) {
    
    std::set<int> nodeIDs;
    for (const auto &ap : trueAPs) {
        auto it = APToNodeID.find(ap);
        if (it != APToNodeID.end()) {
            nodeIDs.insert(it->second);
        }
    }
    return nodeIDs;
}
```

### 6. Formula Structure Analysis

```cpp
const LTLFormulaNode *findSmallestViolatedSubformula(
    const LTLFormulaNode *root,
    const std::set<int> &violatedNodeIDs,
    ViolationType violationType) {
    
    // Search for the smallest subformula that contains the violated nodes
    // and matches the violation type
    
    if (violationType == ViolationType::LEAK) {
        // Look for Eventually nodes (F(ap_2))
        return findNodeByType(root, LTLNodeType::Eventually, violatedNodeIDs);
    } else if (violationType == ViolationType::DOUBLE_FREE) {
        // Look for Implies nodes (ap_2 -> X(G(!ap_2)))
        return findNodeByType(root, LTLNodeType::Implies, violatedNodeIDs);
    }
    
    return root; // Fallback to root
}
```

## Implementation Steps

### Step 1: Modify DSLMonitor::create

```cpp
std::unique_ptr<DSLMonitor> DSLMonitor::create(...) {
    // 1. Build original formula
    spot::formula originalFormula = spot::parse_infix_psl(infix).f;
    
    // 2. Build negated formula
    spot::formula negatedFormula = spot::formula::Not(originalFormula);
    
    // 3. Build negated automaton
    spot::translator trans;
    trans.set_type(spot::postprocessor::TGBA);
    trans.set_pref(spot::postprocessor::Deterministic);
    spot::twa_graph_ptr negatedAut = trans.run(negatedFormula);
    
    // 4. Store both
    R.NegatedAutomaton = negatedAut;
    R.OriginalFormula = originalFormula;
    R.OriginalFormulaBuilder = LTLFormulaBuilder(originalFormula);
    
    // 5. Build AP to node ID mapping
    R.APToNodeID = buildAPToNodeIDMapping(R.OriginalFormulaBuilder);
    
    return R;
}
```

### Step 2: Update Violation Detection

```cpp
// In SpotStepper::step
bool isViolation = false;

if (event.Type == EventType::DeadSymbols || event.Type == EventType::EndAnalysis) {
    if (event.Symbol && UseState && dsl::containsTrackedSymbol(UseState, event.Symbol)) {
        if (isStateAccepting(NegatedAutomaton, CurrentState)) {
            isViolation = true;
        }
    }
} else if (event.Type == EventType::PreCall || event.Type == EventType::PostCall) {
    if (event.Symbol && UseState && dsl::containsTrackedSymbol(UseState, event.Symbol)) {
        if (isStateAccepting(NegatedAutomaton, CurrentState)) {
            isViolation = true;
        }
    }
}

if (isViolation) {
    std::string msg = analyzeViolationFromOriginalFormula(
        OriginalFormulaBuilder, event, fromState, CurrentState, trueAPs);
    // ... rest of violation handling
}
```

## Benefits of This Approach

1. **Standard Model Checking**: Uses negated automaton (accepting = violation)
2. **Formula-Based Diagnostics**: Extracts messages from original formula structure
3. **Precise Violation Detection**: Maps APs to specific formula nodes
4. **Maintainable**: Diagnostic messages come from formula, not hardcoded
5. **Extensible**: New properties just need new formulas with diagnostics

## Example: Malloc-Free Property

**Original Formula**: `G(ap_1 -> (F(ap_2) & G((ap_2 -> X(G(!(ap_2)))))))`
**Negated Formula**: `!G(ap_1 -> (F(ap_2) & G((ap_2 -> X(G(!(ap_2)))))))`

**AP Mapping**:
- `ap_1` → Node ID 1 (malloc call)
- `ap_2` → Node ID 2 (free call)

**Violation Detection**:
- **Leak**: End in accepting state of negated automaton
- **Double-free**: Free call leads to accepting state of negated automaton

**Diagnostic Extraction**:
- **Leak**: Find Eventually node (F(ap_2)) in original formula
- **Double-free**: Find Implies node (ap_2 -> X(G(!ap_2))) in original formula
